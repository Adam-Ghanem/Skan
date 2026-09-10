from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import re
from typing import Any

from tools.corpus.model import (
    CanonicalRecord,
    CanonicalRecordError,
    parse_record,
    runtime_regex_is_valid,
    stable_record_id,
)
from tools.corpus.sources import SourcePolicy


_MAX_DATABASE_BYTES = 1 << 20
_MAX_LINE_BYTES = 16 << 10
_MAX_PROBES = 256
_MAX_RULES_PER_PROBE = 256
_MAX_PATTERN_BYTES = 4096
_MAX_PORTS = 256
_MAX_FALLBACKS = 16
_MAX_PAYLOAD_BYTES = 4000
_PROBE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_FLOAT = re.compile(rb"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_SPACE = b" \t\r\n\v\f"


class RuntimeCorpusError(ValueError):
    """A runtime database cannot be imported safely into the canonical corpus."""


@dataclass(frozen=True)
class ImportContext:
    source: SourcePolicy
    source_path: str

    def __post_init__(self) -> None:
        if (
            not self.source_path
            or len(self.source_path.encode("utf-8")) > 128
            or "\\" in self.source_path
            or self.source_path.startswith("/")
            or any(part in ("", ".", "..") for part in self.source_path.split("/"))
        ):
            raise RuntimeCorpusError("source_path must be a bounded repository-relative path")


@dataclass
class _Rule:
    strength: str
    fields: dict[str, bytes]
    material: bytes


@dataclass
class _Probe:
    name: str
    transport: str
    rarity: int = 1
    priority: int = 50
    timeout_ms: int | None = None
    ports: tuple[int, ...] = ()
    fallbacks: tuple[str, ...] = ()
    payload: bytes | None = None
    declaration_order: int = 0
    header_material: bytes = b""
    send_material: bytes = b""
    rules: list[_Rule] = field(default_factory=list)


@dataclass
class _OSFingerprint:
    name: str
    runtime_id: str
    address_family: str
    vendor: str | None = None
    os_family: str | None = None
    os_generation: str = ""
    device_type: str = ""
    specificity: int | None = None
    has_address_family: bool = False
    signatures: list[dict[str, Any]] = field(default_factory=list)
    fields: set[str] = field(default_factory=set)


def _without_comment(line: bytes) -> bytes:
    quoted = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quoted and character == ord("\\"):
            escaped = True
            continue
        if character == ord('"'):
            quoted = not quoted
        elif not quoted and character == ord("#"):
            return line[:index]
    return line


def _tokenize(line: bytes, line_number: int) -> list[bytes]:
    tokens: list[bytes] = []
    index = 0
    while index < len(line):
        while index < len(line) and line[index] in _SPACE:
            index += 1
        if index == len(line):
            break
        token = bytearray()
        quoted = False
        while index < len(line):
            character = line[index]
            index += 1
            if character == ord('"'):
                quoted = not quoted
                continue
            if character == ord("\\"):
                if index == len(line):
                    raise RuntimeCorpusError(f"line {line_number}: trailing escape")
                escaped = line[index]
                index += 1
                if escaped == ord("x") and index + 1 < len(line):
                    pair = line[index : index + 2]
                    if pair[0] in _HEX_DIGITS and pair[1] in _HEX_DIGITS:
                        token.append(int(pair, 16))
                        index += 2
                    else:
                        token.extend(b"\\x")
                else:
                    decoded = {
                        ord("r"): ord("\r"),
                        ord("n"): ord("\n"),
                        ord("t"): ord("\t"),
                        ord("\\"): ord("\\"),
                        ord('"'): ord('"'),
                    }.get(escaped)
                    if decoded is None:
                        token.extend((ord("\\"), escaped))
                    else:
                        token.append(decoded)
            elif not quoted and character in _SPACE:
                break
            else:
                token.append(character)
        if quoted:
            raise RuntimeCorpusError(f"line {line_number}: unterminated quote")
        tokens.append(bytes(token))
    return tokens


def _ascii(value: bytes, context: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeCorpusError(f"{context} must be ASCII") from error


def _text(value: bytes, context: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeCorpusError(f"{context} must be UTF-8") from error


def _assignments(tokens: list[bytes], directive: str, line_number: int) -> dict[str, bytes]:
    fields: dict[str, bytes] = {}
    for token in tokens:
        key_bytes, separator, value = token.partition(b"=")
        if not separator or not key_bytes or not value:
            raise RuntimeCorpusError(f"line {line_number}: malformed {directive} assignment")
        key = _ascii(key_bytes, f"line {line_number} {directive} field")
        if key in fields:
            raise RuntimeCorpusError(
                f"line {line_number}: duplicate {directive} field: {key}"
            )
        fields[key] = value
    return fields


def _unsigned(value: bytes, field_name: str, minimum: int, maximum: int) -> int:
    text = _ascii(value, field_name)
    if not text.isdecimal():
        raise RuntimeCorpusError(f"invalid {field_name}")
    try:
        result = int(text)
    except ValueError as error:
        raise RuntimeCorpusError(f"invalid {field_name}") from error
    if not minimum <= result <= maximum:
        raise RuntimeCorpusError(f"invalid {field_name}")
    return result


def _ports(value: bytes) -> tuple[int, ...]:
    expanded: list[int] = []
    for item in value.split(b","):
        if not item:
            raise RuntimeCorpusError("invalid ports")
        start_bytes, separator, end_bytes = item.partition(b"-")
        start = _unsigned(start_bytes, "ports", 1, 65535)
        end = _unsigned(end_bytes, "ports", 1, 65535) if separator else start
        if end < start or end - start + 1 > _MAX_PORTS:
            raise RuntimeCorpusError("invalid ports")
        expanded.extend(range(start, end + 1))
        if len(expanded) > _MAX_PORTS:
            raise RuntimeCorpusError(f"ports exceed {_MAX_PORTS} entries")
    if len(expanded) != len(set(expanded)):
        raise RuntimeCorpusError("ports contain duplicates")
    return tuple(sorted(expanded))


def _fallbacks(value: bytes) -> tuple[str, ...]:
    raw_names = value.split(b",")
    if not 1 <= len(raw_names) <= _MAX_FALLBACKS:
        raise RuntimeCorpusError(f"fallback exceeds {_MAX_FALLBACKS} entries")
    names = tuple(_ascii(name, "fallback name") for name in raw_names)
    if any(_PROBE_NAME.fullmatch(name) is None for name in names):
        raise RuntimeCorpusError("invalid fallback name")
    if len(names) != len(set(names)):
        raise RuntimeCorpusError("fallback contains duplicates")
    return names


def _record(
    kind: str,
    body: dict[str, Any],
    source_record_id: str,
    material: bytes,
    context: ImportContext,
) -> CanonicalRecord:
    policy = context.source
    value: dict[str, Any] = {
        "schema_version": 2,
        "id": "",
        "kind": kind,
        "body": body,
        "provenance": [
            {
                "source_id": policy.id,
                "source_record_id": source_record_id,
                "source_revision": policy.pinned_revision,
                "source_url": policy.source_url,
                "source_license": policy.license_spdx_or_policy,
                "snapshot_hash": policy.expected_hash,
                "record_hash": "sha256:" + hashlib.sha256(material).hexdigest(),
            }
        ],
        "first_imported_revision": policy.pinned_revision,
        "last_verified_revision": policy.pinned_revision,
        "status": "verified",
        "notes": f"Imported from {context.source_path}.",
    }
    try:
        value["id"] = stable_record_id(value)
        return parse_record(value, {policy.id: policy})
    except CanonicalRecordError as error:
        raise RuntimeCorpusError(f"{source_record_id}: {error}") from error


def _probe_from_tokens(tokens: list[bytes], line: bytes, line_number: int, order: int) -> _Probe:
    if len(tokens) < 3:
        raise RuntimeCorpusError(f"line {line_number}: malformed Probe directive")
    transport = _ascii(tokens[1], f"line {line_number} transport").lower()
    if transport not in ("tcp", "udp") or tokens[1] not in (b"TCP", b"UDP"):
        raise RuntimeCorpusError(f"line {line_number}: invalid Probe transport")
    name = _ascii(tokens[2], f"line {line_number} probe name")
    if _PROBE_NAME.fullmatch(name) is None:
        raise RuntimeCorpusError(f"line {line_number}: invalid probe name")
    fields = _assignments(tokens[3:], "Probe", line_number)
    supported = {"rarity", "priority", "timeout", "ports", "fallback", "protocol"}
    unknown = sorted(set(fields) - supported)
    if unknown:
        raise RuntimeCorpusError(f"line {line_number}: unknown Probe field: {unknown[0]}")
    if "protocol" in fields and _ascii(fields["protocol"], "protocol") != transport:
        raise RuntimeCorpusError(f"line {line_number}: Probe protocol does not match transport")
    return _Probe(
        name=name,
        transport=transport,
        rarity=_unsigned(fields["rarity"], "rarity", 1, (1 << 32) - 1)
        if "rarity" in fields
        else 1,
        priority=_unsigned(fields["priority"], "priority", 1, 100)
        if "priority" in fields
        else 50,
        timeout_ms=_unsigned(fields["timeout"], "timeout", 1, 60000)
        if "timeout" in fields
        else None,
        ports=_ports(fields["ports"]) if "ports" in fields else (),
        fallbacks=_fallbacks(fields["fallback"]) if "fallback" in fields else (),
        declaration_order=order,
        header_material=line,
    )


def _rule_from_tokens(
    tokens: list[bytes], directive: str, line: bytes, line_number: int
) -> _Rule:
    fields = _assignments(tokens[1:], directive, line_number)
    supported = {
        "type",
        "pattern",
        "service",
        "product",
        "version",
        "extra",
        "hostname",
        "tunnel",
        "confidence",
    }
    unknown = sorted(set(fields) - supported)
    if unknown:
        raise RuntimeCorpusError(f"line {line_number}: unknown {directive} field: {unknown[0]}")
    missing = sorted({"pattern", "service", "confidence"} - set(fields))
    if missing:
        raise RuntimeCorpusError(f"line {line_number}: missing {directive} field: {missing[0]}")
    matcher_type = _ascii(fields.get("type", b"prefix"), "matcher type")
    if matcher_type not in ("exact", "prefix", "suffix", "substring", "regex"):
        raise RuntimeCorpusError(f"line {line_number}: invalid matcher type")
    pattern = fields["pattern"]
    if not pattern or len(pattern) > _MAX_PATTERN_BYTES:
        raise RuntimeCorpusError(f"line {line_number}: invalid pattern")
    if matcher_type == "regex" and not runtime_regex_is_valid(pattern):
        raise RuntimeCorpusError(f"line {line_number}: invalid ECMAScript regex")
    confidence_text = _ascii(fields["confidence"], "confidence")
    if _FLOAT.fullmatch(fields["confidence"]) is None:
        raise RuntimeCorpusError(f"line {line_number}: invalid confidence")
    try:
        confidence = float(confidence_text)
    except ValueError as error:
        raise RuntimeCorpusError(f"line {line_number}: invalid confidence") from error
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise RuntimeCorpusError(f"line {line_number}: invalid confidence")
    fields["type"] = matcher_type.encode("ascii")
    fields["confidence"] = repr(confidence).encode("ascii")
    return _Rule("soft" if directive == "softmatch" else "hard", fields, line)


def _pattern_fields(matcher_type: str, pattern: bytes) -> tuple[str | None, str | None]:
    if matcher_type != "regex":
        return None, pattern.hex()
    try:
        text = pattern.decode("utf-8")
    except UnicodeDecodeError:
        return None, pattern.hex()
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        return None, pattern.hex()
    return text, None


def parse_service_runtime(text: bytes, context: ImportContext) -> tuple[CanonicalRecord, ...]:
    if not isinstance(text, bytes):
        raise RuntimeCorpusError("service runtime input must be bytes")
    if len(text) > _MAX_DATABASE_BYTES:
        raise RuntimeCorpusError(f"database exceeds {_MAX_DATABASE_BYTES} bytes")
    if "active_probe" not in context.source.approved_data_classes or "service_matcher" not in context.source.approved_data_classes:
        raise RuntimeCorpusError("source policy does not authorize service runtime records")

    probes: list[_Probe] = []
    current: _Probe | None = None
    for line_number, raw_line in enumerate(text.split(b"\n"), 1):
        if len(raw_line) > _MAX_LINE_BYTES:
            raise RuntimeCorpusError(f"line {line_number} exceeds {_MAX_LINE_BYTES} bytes")
        content = _without_comment(raw_line).strip(_SPACE)
        if not content:
            continue
        tokens = _tokenize(content, line_number)
        directive = _ascii(tokens[0], f"line {line_number} directive")
        if directive == "Probe":
            if len(probes) >= _MAX_PROBES:
                raise RuntimeCorpusError(f"probe count exceeds {_MAX_PROBES}")
            current = _probe_from_tokens(tokens, content, line_number, len(probes))
            if any(probe.name == current.name for probe in probes):
                raise RuntimeCorpusError(f"line {line_number}: duplicate probe name: {current.name}")
            probes.append(current)
        elif directive == "send":
            if current is None or len(tokens) != 2:
                raise RuntimeCorpusError(f"line {line_number}: malformed send directive")
            if current.payload is not None:
                raise RuntimeCorpusError(f"line {line_number}: duplicate send directive")
            if len(tokens[1]) > _MAX_PAYLOAD_BYTES:
                raise RuntimeCorpusError(f"line {line_number}: payload exceeds {_MAX_PAYLOAD_BYTES} bytes")
            current.payload = tokens[1]
            current.send_material = content
        elif directive in ("match", "softmatch"):
            if current is None:
                raise RuntimeCorpusError(f"line {line_number}: {directive} without Probe")
            if len(current.rules) >= _MAX_RULES_PER_PROBE:
                raise RuntimeCorpusError(
                    f"line {line_number}: rule count exceeds {_MAX_RULES_PER_PROBE}"
                )
            current.rules.append(_rule_from_tokens(tokens, directive, content, line_number))
        else:
            raise RuntimeCorpusError(f"line {line_number}: unknown directive: {directive}")

    if not probes:
        raise RuntimeCorpusError("service runtime contains no probes")
    by_name = {probe.name: probe for probe in probes}
    for probe in probes:
        if probe.payload is None:
            raise RuntimeCorpusError(f"missing send directive for probe: {probe.name}")
        for fallback in probe.fallbacks:
            target = by_name.get(fallback)
            if target is None:
                raise RuntimeCorpusError(f"unresolved fallback: {fallback}")
            if target is probe:
                raise RuntimeCorpusError(f"self fallback: {fallback}")
            if target.transport != probe.transport:
                raise RuntimeCorpusError(f"cross-transport fallback: {fallback}")

    records: list[CanonicalRecord] = []
    for probe in probes:
        probe_identity = f"{context.source_path}:probe:{probe.name}"
        records.append(
            _record(
                "active_probe",
                {
                    "probe_name": probe.name,
                    "transport": probe.transport,
                    "payload_hex": probe.payload.hex(),
                    "rarity": probe.rarity,
                    "priority": probe.priority,
                    "timeout_ms": probe.timeout_ms,
                    "ports": list(probe.ports),
                    "fallback_probe_names": list(probe.fallbacks),
                    "declaration_order": probe.declaration_order,
                },
                probe_identity,
                probe.header_material + b"\n" + probe.send_material,
                context,
            )
        )
        for rule_order, rule in enumerate(probe.rules):
            matcher_type = _ascii(rule.fields["type"], "matcher type")
            pattern, pattern_hex = _pattern_fields(matcher_type, rule.fields["pattern"])
            records.append(
                _record(
                    "service_matcher",
                    {
                        "probe_name": probe.name,
                        "matcher_type": matcher_type,
                        "pattern": pattern,
                        "pattern_hex": pattern_hex,
                        "strength": rule.strength,
                        "service": _text(rule.fields["service"], "service"),
                        "product": _text(rule.fields["product"], "product")
                        if "product" in rule.fields
                        else None,
                        "version_template": _text(rule.fields["version"], "version")
                        if "version" in rule.fields
                        else None,
                        "extra": _text(rule.fields["extra"], "extra")
                        if "extra" in rule.fields
                        else None,
                        "hostname_template": _text(rule.fields["hostname"], "hostname")
                        if "hostname" in rule.fields
                        else None,
                        "tunnel": _text(rule.fields["tunnel"], "tunnel")
                        if "tunnel" in rule.fields
                        else None,
                        "confidence": float(_ascii(rule.fields["confidence"], "confidence")),
                        "rule_order": rule_order,
                        "cpe": [],
                    },
                    f"{probe_identity}:rule:{rule_order}",
                    rule.material,
                    context,
                )
            )
    return tuple(records)


def _runtime_text(value: bytes, context: str) -> str:
    return _text(value, context)


def _udp_hex(value: bytes, line_number: int) -> str:
    if not value or len(value) % 2 or len(value) // 2 > 512:
        raise RuntimeCorpusError(f"line {line_number}: invalid UDP payload")
    if any(character not in _HEX_DIGITS for character in value):
        raise RuntimeCorpusError(f"line {line_number}: invalid UDP payload")
    return value.decode("ascii").lower()


def parse_udp_runtime(text: bytes, context: ImportContext) -> tuple[CanonicalRecord, ...]:
    if not isinstance(text, bytes):
        raise RuntimeCorpusError("UDP runtime input must be bytes")
    if len(text) > _MAX_DATABASE_BYTES:
        raise RuntimeCorpusError(f"database exceeds {_MAX_DATABASE_BYTES} bytes")
    if "udp_probe" not in context.source.approved_data_classes:
        raise RuntimeCorpusError("source policy does not authorize UDP runtime records")

    records: list[CanonicalRecord] = []
    names: set[str] = set()
    ports: set[int] = set()
    has_default = False
    for line_number, raw_line in enumerate(text.split(b"\n"), 1):
        if len(raw_line) > _MAX_LINE_BYTES:
            raise RuntimeCorpusError(f"line {line_number} exceeds {_MAX_LINE_BYTES} bytes")
        content = raw_line.strip(_SPACE)
        if not content or content.startswith(b"#"):
            continue
        tokens = content.split()
        if len(tokens) != 6 or tokens[0] != b"probe":
            raise RuntimeCorpusError(f"line {line_number}: malformed UDP probe")
        name = _ascii(tokens[1], f"line {line_number} UDP probe name")
        destination_port = _unsigned(tokens[2], "UDP destination port", 0, 65535)
        protocol_hint = _ascii(tokens[3], f"line {line_number} UDP protocol hint")
        max_response_bytes = _unsigned(
            tokens[4], "UDP max_response_bytes", 1, 1 << 20
        )
        payload_hex = _udp_hex(tokens[5], line_number)
        if name in names:
            raise RuntimeCorpusError(f"line {line_number}: duplicate UDP probe name: {name}")
        if destination_port in ports:
            raise RuntimeCorpusError(
                f"line {line_number}: duplicate UDP port: {destination_port}"
            )
        if (destination_port == 0) != (name == "DEFAULT"):
            raise RuntimeCorpusError("port 0 is reserved for DEFAULT")
        if len(records) >= _MAX_PROBES:
            raise RuntimeCorpusError(f"UDP probe count exceeds {_MAX_PROBES}")
        names.add(name)
        ports.add(destination_port)
        if destination_port == 0:
            has_default = True
        records.append(
            _record(
                "udp_probe",
                {
                    "name": name,
                    "destination_port": destination_port,
                    "protocol_hint": protocol_hint,
                    "max_response_bytes": max_response_bytes,
                    "payload_hex": payload_hex,
                    "declaration_order": len(records),
                },
                f"{context.source_path}:probe:{name}",
                content,
                context,
            )
        )
    if not records:
        raise RuntimeCorpusError("UDP runtime contains no probes")
    if not has_default:
        raise RuntimeCorpusError("missing DEFAULT UDP probe")
    return tuple(records)


_OS_NUMERIC_DIRECTIVES = {
    b"TTL": ("ttl", 0, 255),
    b"WINDOW": ("window", 0, 65535),
    b"MSS": ("mss", 0, 65535),
    b"WSCALE": ("window_scale", 0, 255),
    b"TCP_FLAGS": ("tcp_flags", 0, 255),
    b"ICMP_TTL": ("icmp_ttl", 0, 255),
    b"ICMP_TYPE": ("icmp_type", 0, 255),
    b"ICMP_CODE": ("icmp_code", 0, 255),
    b"UDP_PAYLOAD_LENGTH": ("udp_payload_length", 0, 65535),
}
_OS_RANGE_DIRECTIVES = {
    b"TTL_RANGE": ("ttl", 0, 255),
    b"WINDOW_RANGE": ("window", 0, 65535),
    b"ICMP_TTL_RANGE": ("icmp_ttl", 0, 255),
    b"UDP_PAYLOAD_RANGE": ("udp_payload_length", 0, 65535),
}
_OS_BOOLEAN_DIRECTIVES = {
    b"DF": "dont_fragment",
    b"SACK": "sack_permitted",
    b"TIMESTAMP": "timestamps",
    b"RESPONSE_PRESENCE": "response_presence",
}
_OS_TEXT_DIRECTIVES = {
    b"ACK_BEHAVIOR": "ack_behavior",
    b"SEQUENCE_BEHAVIOR": "sequence_behavior",
    b"RESPONSE_BEHAVIOR": "response_behavior",
    b"UDP_RESPONSE_BEHAVIOR": "udp_response_behavior",
}


def _os_boolean(value: bytes, line_number: int) -> bool:
    normalized = value.strip(b" \t\r")
    if normalized in (b"Y", b"YES", b"1"):
        return True
    if normalized in (b"N", b"NO", b"0"):
        return False
    raise RuntimeCorpusError(f"line {line_number}: invalid OS boolean")


def _os_range(value: bytes, field: str, minimum: int, maximum: int) -> list[int]:
    lower, separator, upper = value.partition(b"-")
    if not separator or not lower or not upper or b"-" in upper:
        raise RuntimeCorpusError(f"invalid {field} range")
    parsed_lower = _unsigned(lower.strip(b" \t\r"), field, minimum, maximum)
    parsed_upper = _unsigned(upper.strip(b" \t\r"), field, minimum, maximum)
    if parsed_upper < parsed_lower:
        raise RuntimeCorpusError(f"invalid {field} range")
    return [parsed_lower, parsed_upper]


def _finalize_os(
    fingerprint: _OSFingerprint | None,
    material: bytes,
    context: ImportContext,
    records: list[CanonicalRecord],
) -> None:
    if fingerprint is None:
        return
    if (
        fingerprint.vendor is None
        or fingerprint.os_family is None
        or not fingerprint.signatures
        or (fingerprint.address_family == "ipv6" and not fingerprint.has_address_family)
    ):
        raise RuntimeCorpusError(f"incomplete OS fingerprint: {fingerprint.name}")
    specificity = fingerprint.specificity if fingerprint.specificity is not None else len(fingerprint.signatures)
    records.append(
        _record(
            "os_fingerprint",
            {
                "runtime_id": fingerprint.runtime_id,
                "name": fingerprint.name,
                "vendor": fingerprint.vendor,
                "os_family": fingerprint.os_family,
                "os_generation": fingerprint.os_generation,
                "device_type": fingerprint.device_type,
                "address_family": fingerprint.address_family,
                "specificity": specificity,
                "signatures": fingerprint.signatures,
            },
            f"{context.source_path}:fingerprint:{fingerprint.runtime_id}",
            material,
            context,
        )
    )


def parse_os_runtime(
    text: bytes, address_family: str, context: ImportContext
) -> tuple[CanonicalRecord, ...]:
    if not isinstance(text, bytes):
        raise RuntimeCorpusError("OS runtime input must be bytes")
    if address_family not in ("ipv4", "ipv6"):
        raise RuntimeCorpusError("address_family must be ipv4 or ipv6")
    if len(text) > _MAX_DATABASE_BYTES:
        raise RuntimeCorpusError(f"database exceeds {_MAX_DATABASE_BYTES} bytes")
    if "os_fingerprint" not in context.source.approved_data_classes:
        raise RuntimeCorpusError("source policy does not authorize OS runtime records")

    records: list[CanonicalRecord] = []
    names: set[str] = set()
    ids: set[str] = set()
    current: _OSFingerprint | None = None
    material = bytearray()
    lines = text.split(b"\n")
    for line_number, raw_line in enumerate(lines, 1):
        if len(raw_line) > 4096:
            raise RuntimeCorpusError(f"line {line_number} exceeds 4096 bytes")
        canonical_line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
        canonical_material = canonical_line + (b"\n" if line_number < len(lines) else b"")
        content = raw_line.strip(b" \t\r")
        comment = content.find(b"#")
        if comment >= 0:
            content = content[:comment].strip(b" \t\r")
        if content.startswith(b"Fingerprint "):
            _finalize_os(current, bytes(material), context, records)
            material = bytearray(canonical_material)
            name = _runtime_text(content[len(b"Fingerprint ") :].strip(b" \t\r"), "OS fingerprint name")
            if not name:
                raise RuntimeCorpusError(f"line {line_number}: empty OS fingerprint name")
            if name in names:
                raise RuntimeCorpusError(f"line {line_number}: duplicate OS fingerprint name: {name}")
            if len(records) >= _MAX_PROBES:
                raise RuntimeCorpusError(f"OS fingerprint count exceeds {_MAX_PROBES}")
            names.add(name)
            current = _OSFingerprint(name=name, runtime_id=name, address_family=address_family)
            continue
        if current is not None:
            material.extend(canonical_material)
        if not content:
            continue
        if current is None:
            raise RuntimeCorpusError(f"line {line_number}: OS directive without Fingerprint")
        if content.startswith(b"Class "):
            if "Class" in current.fields:
                raise RuntimeCorpusError(f"line {line_number}: duplicate OS field: Class")
            values = [part.strip(b" \t\r") for part in content[len(b"Class ") :].split(b"|")]
            if len(values) not in (2, 3, 4) or any(not value for value in values):
                raise RuntimeCorpusError(f"line {line_number}: malformed OS Class")
            current.vendor = _runtime_text(values[0], "OS vendor")
            current.os_family = _runtime_text(values[1], "OS family")
            current.os_generation = _runtime_text(values[2], "OS generation") if len(values) >= 3 else ""
            current.device_type = _runtime_text(values[3], "OS device type") if len(values) == 4 else ""
            current.fields.add("Class")
            continue
        key, separator, value = content.partition(b"=")
        if not separator or not key or not value:
            raise RuntimeCorpusError(f"line {line_number}: malformed OS directive")
        key = key.strip(b" \t\r")
        value = value.strip(b" \t\r")
        if not key or not value:
            raise RuntimeCorpusError(f"line {line_number}: malformed OS directive")
        key_text = _ascii(key, f"line {line_number} OS directive")
        if key_text in current.fields:
            raise RuntimeCorpusError(f"line {line_number}: duplicate OS field: {key_text}")
        signature_field = (
            _OS_NUMERIC_DIRECTIVES.get(key)
            or _OS_RANGE_DIRECTIVES.get(key)
        )
        if signature_field is None and key in _OS_BOOLEAN_DIRECTIVES:
            signature_field = (_OS_BOOLEAN_DIRECTIVES[key], 0, 0)
        if signature_field is None and key == b"TCP_OPTIONS":
            signature_field = ("tcp_options", 0, 0)
        if signature_field is None and key in _OS_TEXT_DIRECTIVES:
            signature_field = (_OS_TEXT_DIRECTIVES[key], 0, 0)
        if signature_field is not None and signature_field[0] in current.fields:
            raise RuntimeCorpusError(
                f"line {line_number}: duplicate OS signature field: {signature_field[0]}"
            )
        if key == b"ID":
            runtime_id = _runtime_text(value, "OS fingerprint ID")
            if runtime_id in ids:
                raise RuntimeCorpusError(f"line {line_number}: duplicate OS fingerprint ID: {runtime_id}")
            if current.runtime_id != current.name:
                raise RuntimeCorpusError(f"line {line_number}: duplicate OS field: ID")
            current.runtime_id = runtime_id
            ids.add(runtime_id)
        elif key == b"SPECIFICITY":
            current.specificity = _unsigned(value, "OS specificity", 1, 65535)
        elif key == b"ADDRESS_FAMILY":
            parsed_family = _ascii(value, "OS address family").lower()
            if parsed_family not in ("ipv4", "ipv6"):
                raise RuntimeCorpusError(f"line {line_number}: invalid OS address family")
            if parsed_family != address_family:
                raise RuntimeCorpusError("mixed OS address family")
            current.has_address_family = True
        elif key in _OS_NUMERIC_DIRECTIVES:
            field, minimum, maximum = _OS_NUMERIC_DIRECTIVES[key]
            current.signatures.append(
                {"field": field, "operator": "eq", "value": _unsigned(value, field, minimum, maximum)}
            )
            current.fields.add(field)
            continue
        elif key in _OS_RANGE_DIRECTIVES:
            field, minimum, maximum = _OS_RANGE_DIRECTIVES[key]
            current.signatures.append(
                {"field": field, "operator": "range", "value": _os_range(value, field, minimum, maximum)}
            )
            current.fields.add(field)
            continue
        elif key in _OS_BOOLEAN_DIRECTIVES:
            field = _OS_BOOLEAN_DIRECTIVES[key]
            current.signatures.append({"field": field, "operator": "bool", "value": _os_boolean(value, line_number)})
            current.fields.add(field)
            continue
        elif key == b"TCP_OPTIONS":
            aliases = {b"NOP": "NOP", b"MSS": "MSS", b"WS": "WS", b"WSCALE": "WS", b"SACK": "SACK", b"TS": "TS", b"TIMESTAMP": "TS"}
            options = []
            for option in value.split(b","):
                normalized = option.strip(b" \t\r")
                if normalized not in aliases:
                    raise RuntimeCorpusError(f"line {line_number}: invalid TCP option")
                options.append(aliases[normalized])
            if not options:
                raise RuntimeCorpusError(f"line {line_number}: invalid TCP option")
            current.signatures.append({"field": "tcp_options", "operator": "tcp_options", "value": options})
            current.fields.add("tcp_options")
            continue
        elif key in _OS_TEXT_DIRECTIVES:
            field = _OS_TEXT_DIRECTIVES[key]
            current.signatures.append({"field": field, "operator": "text", "value": _runtime_text(value, field)})
            current.fields.add(field)
            continue
        else:
            raise RuntimeCorpusError(f"line {line_number}: unknown OS directive: {key_text}")
        current.fields.add(key_text)
    _finalize_os(current, bytes(material), context, records)
    if not records:
        raise RuntimeCorpusError("OS runtime contains no fingerprints")
    identities = [record.body.runtime_id for record in records]
    if len(identities) != len(set(identities)):
        raise RuntimeCorpusError("duplicate OS fingerprint ID")
    return tuple(records)
