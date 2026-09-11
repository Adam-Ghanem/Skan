from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable

from tools.corpus.legacy_udp import LegacyUDPError, compile_legacy_udp
from tools.corpus.model import (
    ActiveProbeSemantics,
    CanonicalRecord,
    OSFingerprintSemantics,
    ServiceMatcherSemantics,
    UDPProbeSemantics,
    parse_record,
    record_to_mapping,
)
from tools.corpus.sources import load_source_manifest


class CompilerError(ValueError):
    """Canonical records cannot be compiled into the bounded runtime artifacts."""


@dataclass(frozen=True)
class CompiledCorpus:
    service_probes: bytes
    udp_probes: bytes
    ipv4_os: bytes
    ipv6_os: bytes
    manifest: bytes


def _quote(value: bytes) -> str:
    escaped: list[str] = []
    for byte in value:
        if byte == 13:
            escaped.append("\\r")
        elif byte == 10:
            escaped.append("\\n")
        elif byte == 9:
            escaped.append("\\t")
        elif byte == 34:
            escaped.append('\\"')
        elif byte == 92:
            escaped.append("\\\\")
        elif 32 <= byte <= 126:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return '"' + "".join(escaped) + '"'


def _text_token(value: str) -> str:
    return _quote(value.encode("utf-8"))


def validate_runtime_graph(records: Iterable[CanonicalRecord]) -> tuple[CanonicalRecord, ...]:
    collected = tuple(records)
    groups: dict[str, list[CanonicalRecord]] = {kind: [] for kind in ("active_probe", "service_matcher", "udp_probe", "os_fingerprint")}
    for record in collected:
        if not isinstance(record, CanonicalRecord) or record.kind not in groups:
            raise CompilerError("compiler input contains an unsupported record")
        if record.status != "verified":
            raise CompilerError("all records must be verified")
        groups[record.kind].append(record)
    if any(not groups[kind] for kind in groups):
        raise CompilerError("all four runtime record kinds must be non-empty")

    probes = [record.body for record in groups["active_probe"]]
    if not all(isinstance(body, ActiveProbeSemantics) for body in probes):
        raise CompilerError("active_probe body is invalid")
    names = [body.probe_name for body in probes]
    if len(names) != len(set(names)):
        raise CompilerError("duplicate probe name")
    if tuple(sorted(body.declaration_order for body in probes)) != tuple(range(len(probes))):
        raise CompilerError("active probe declaration_order values must be contiguous from zero")
    by_name = {body.probe_name: body for body in probes}
    for probe in probes:
        for fallback in probe.fallback_probe_names:
            target = by_name.get(fallback)
            if target is None:
                raise CompilerError("unresolved fallback")
            if target is probe:
                raise CompilerError("self fallback")
            if target.transport != probe.transport:
                raise CompilerError("cross-transport fallback")

    matchers = [record.body for record in groups["service_matcher"]]
    if not all(isinstance(body, ServiceMatcherSemantics) for body in matchers):
        raise CompilerError("service_matcher body is invalid")
    for matcher in matchers:
        if matcher.probe_name not in by_name:
            raise CompilerError("unresolved matcher probe")
        if matcher.cpe:
            raise CompilerError("runtime service grammar cannot encode CPE values")
    for probe_name in by_name:
        orders = sorted(matcher.rule_order for matcher in matchers if matcher.probe_name == probe_name)
        if orders and tuple(orders) != tuple(range(len(orders))):
            raise CompilerError("matcher rule_order values must be contiguous from zero")

    udp = [record.body for record in groups["udp_probe"]]
    if not all(isinstance(body, UDPProbeSemantics) for body in udp):
        raise CompilerError("udp_probe body is invalid")
    udp_names = [body.name for body in udp]
    if len(udp_names) != len(set(udp_names)):
        raise CompilerError("duplicate UDP name")
    ports = [body.destination_port for body in udp if body.destination_port != 0]
    if len(ports) != len(set(ports)):
        raise CompilerError("duplicate UDP port")
    defaults = [body for body in udp if body.destination_port == 0]
    if len(defaults) != 1 or defaults[0].name != "DEFAULT":
        raise CompilerError("exactly one DEFAULT UDP probe is required")

    fingerprints = [record.body for record in groups["os_fingerprint"]]
    if not all(isinstance(body, OSFingerprintSemantics) for body in fingerprints):
        raise CompilerError("os_fingerprint body is invalid")
    all_ids = [body.runtime_id for body in fingerprints]
    if len(all_ids) != len(set(all_ids)):
        raise CompilerError("duplicate OS runtime ID")
    all_names = [body.name for body in fingerprints]
    if len(all_names) != len(set(all_names)):
        raise CompilerError("duplicate OS fingerprint name")
    for family in ("ipv4", "ipv6"):
        ids = [body.runtime_id for body in fingerprints if body.address_family == family]
        if not ids:
            raise CompilerError("all four runtime record kinds must be non-empty")
        if len(ids) != len(set(ids)):
            raise CompilerError("duplicate OS runtime ID")
    sources = load_source_manifest(Path(__file__).resolve().parents[2] / "corpus" / "sources" / "sources.json")
    identifiers: set[str] = set()
    for record in collected:
        try:
            parse_record(record_to_mapping(record), sources)
        except Exception as exc:
            raise CompilerError(f"canonical record validation failed: {exc}") from exc
        if record.id in identifiers:
            raise CompilerError("duplicate canonical record ID")
        identifiers.add(record.id)
    return collected


def _service(records: tuple[CanonicalRecord, ...]) -> bytes:
    probes = sorted((r.body for r in records if r.kind == "active_probe"), key=lambda body: body.declaration_order)
    matchers = [r.body for r in records if r.kind == "service_matcher"]
    lines: list[str] = []
    for probe in probes:
        assert isinstance(probe, ActiveProbeSemantics)
        fields = [f"rarity={probe.rarity}", f"priority={probe.priority}"]
        if probe.timeout_ms is not None:
            fields.append(f"timeout={probe.timeout_ms}")
        if probe.ports:
            fields.append("ports=" + ",".join(str(port) for port in probe.ports))
        if probe.fallback_probe_names:
            fields.append("fallback=" + ",".join(probe.fallback_probe_names))
        fields.append(f"protocol={probe.transport}")
        lines.append(f"Probe {probe.transport.upper()} {probe.probe_name} " + " ".join(fields))
        lines.append("send " + _quote(bytes.fromhex(probe.payload_hex)))
        rules = sorted((m for m in matchers if isinstance(m, ServiceMatcherSemantics) and m.probe_name == probe.probe_name), key=lambda body: body.rule_order)
        for rule in rules:
            pattern = rule.pattern.encode("utf-8") if rule.pattern is not None else bytes.fromhex(rule.pattern_hex or "")
            fields = [f"type={rule.matcher_type}", "pattern=" + _quote(pattern), f"service={_text_token(rule.service)}"]
            for key, value in (("product", rule.product), ("version", rule.version_template), ("extra", rule.extra), ("hostname", rule.hostname_template), ("tunnel", rule.tunnel)):
                if value is not None:
                    fields.append(key + "=" + _text_token(value))
            fields.append("confidence=" + repr(rule.confidence))
            lines.append(("softmatch" if rule.strength == "soft" else "match") + " " + " ".join(fields))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _os(records: tuple[CanonicalRecord, ...], family: str) -> bytes:
    fields = {"ttl": "TTL", "window": "WINDOW", "mss": "MSS", "window_scale": "WSCALE", "tcp_flags": "TCP_FLAGS", "icmp_ttl": "ICMP_TTL", "icmp_type": "ICMP_TYPE", "icmp_code": "ICMP_CODE", "udp_payload_length": "UDP_PAYLOAD_LENGTH", "dont_fragment": "DF", "sack_permitted": "SACK", "timestamps": "TIMESTAMP", "tcp_options": "TCP_OPTIONS", "udp_response_behavior": "UDP_RESPONSE_BEHAVIOR", "response_presence": "RESPONSE_PRESENCE", "ack_behavior": "ACK_BEHAVIOR", "sequence_behavior": "SEQUENCE_BEHAVIOR", "response_behavior": "RESPONSE_BEHAVIOR"}
    lines: list[str] = []
    for body in sorted((r.body for r in records if r.kind == "os_fingerprint" and isinstance(r.body, OSFingerprintSemantics) and r.body.address_family == family), key=lambda item: item.runtime_id):
        lines.extend([f"Fingerprint {body.name}", f"ID={body.runtime_id}", f"SPECIFICITY={body.specificity}", f"ADDRESS_FAMILY={family.upper().replace('IPV', 'IPv')}"])
        components = [body.vendor, body.os_family] + ([body.os_generation] if body.os_generation else []) + ([body.device_type] if body.device_type else [])
        lines.append("Class " + " | ".join(components))
        for signature in body.signatures:
            key = fields[signature.field]
            if signature.operator == "range": key += "_RANGE"
            value = signature.value
            if signature.operator == "range": rendered = f"{value[0]}-{value[1]}"
            elif signature.operator == "bool": rendered = "Y" if value else "N"
            elif signature.operator == "tcp_options": rendered = ",".join(value)
            else: rendered = str(value)
            lines.append(f"{key}={rendered}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def compile_corpus(records: Iterable[CanonicalRecord]) -> CompiledCorpus:
    validated = validate_runtime_graph(records)
    service = _service(validated)
    sources = load_source_manifest(Path(__file__).resolve().parents[2] / "corpus" / "sources" / "sources.json")
    try:
        udp = compile_legacy_udp((r for r in validated if r.kind == "udp_probe"), sources).encode("utf-8")
    except LegacyUDPError as exc:
        raise CompilerError(str(exc)) from exc
    ipv4, ipv6 = _os(validated, "ipv4"), _os(validated, "ipv6")
    artifacts = {"service-probes.db": service, "udp-probes.db": udp, "os-fingerprints.db": ipv4, "os-fingerprints-v6.db": ipv6}
    manifest = json.dumps({"artifacts": {name: "sha256:" + hashlib.sha256(value).hexdigest() for name, value in sorted(artifacts.items())}, "record_counts": {kind: sum(r.kind == kind for r in validated) for kind in ("active_probe", "service_matcher", "udp_probe", "os_fingerprint")}, "record_ids": sorted(record.id for record in validated)}, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    return CompiledCorpus(service, udp, ipv4, ipv6, manifest)


def _validate_compiled(compiled: CompiledCorpus) -> None:
    if not isinstance(compiled, CompiledCorpus):
        raise CompilerError("compiled corpus is invalid")
    try:
        manifest = json.loads(compiled.manifest)
        artifacts = manifest["artifacts"]
        counts = manifest["record_counts"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CompilerError("compiled manifest is invalid") from exc
    values = {"service-probes.db": compiled.service_probes, "udp-probes.db": compiled.udp_probes, "os-fingerprints.db": compiled.ipv4_os, "os-fingerprints-v6.db": compiled.ipv6_os}
    if set(artifacts) != set(values) or set(counts) != {"active_probe", "service_matcher", "udp_probe", "os_fingerprint"} or not isinstance(manifest.get("record_ids"), list):
        raise CompilerError("compiled manifest shape is invalid")
    if any(artifacts[name] != "sha256:" + hashlib.sha256(value).hexdigest() for name, value in values.items()) or any(type(value) is not int or value < 1 for value in counts.values()):
        raise CompilerError("compiled manifest does not match artifacts")


def write_compiled_corpus(output_dir: Path, compiled: CompiledCorpus) -> None:
    _validate_compiled(compiled)
    if output_dir.is_symlink() or any((output_dir / name).is_symlink() for name in ("service-probes.db", "udp-probes.db", "os-fingerprints.db", "os-fingerprints-v6.db", "manifest.json")):
        raise CompilerError("compiled output path must not contain symlinks")
    files = {"service-probes.db": compiled.service_probes, "udp-probes.db": compiled.udp_probes, "os-fingerprints.db": compiled.ipv4_os, "os-fingerprints-v6.db": compiled.ipv6_os, "manifest.json": compiled.manifest}
    output_dir.mkdir(parents=True, exist_ok=True)
    staged: dict[str, Path] = {}
    try:
        for name, data in files.items():
            with tempfile.NamedTemporaryFile(dir=output_dir, prefix=f".{name}.", delete=False) as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
                staged[name] = Path(stream.name)
        for name in ("service-probes.db", "udp-probes.db", "os-fingerprints.db", "os-fingerprints-v6.db", "manifest.json"):
            os.replace(staged.pop(name), output_dir / name)
    except OSError as exc:
        raise CompilerError(f"cannot atomically write compiled corpus: {exc}") from exc
    finally:
        for path in staged.values(): path.unlink(missing_ok=True)
