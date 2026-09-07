from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id


_SOURCE_ID = "skan-first-party"
_SOURCE_REVISION = "repository"
_SOURCE_URL = "https://github.com/Adam-Ghanem/Skan/tree/main/data"
_SOURCE_LICENSE = "MIT"
_ALLOWED_MATCH_TYPES = {"exact", "prefix", "suffix", "substring", "regex"}
_PROBE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_FALLBACKS = 16
_MAX_TIMEOUT_MS = 60000
_MAX_PATTERN_BYTES = 4096


def _fail(path: Path, line_number: int, message: str) -> ValueError:
    return ValueError(f"{path.name}:{line_number}: {message}")


def _without_comment(value: str) -> str:
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted and character == "\\":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
        elif not quoted and character == "#":
            return value[:index]
    return value


def _hex_value(character: str) -> int:
    if "0" <= character <= "9":
        return ord(character) - ord("0")
    if "a" <= character <= "f":
        return ord(character) - ord("a") + 10
    if "A" <= character <= "F":
        return ord(character) - ord("A") + 10
    return -1


def _tokenize(line: str, path: Path, line_number: int) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(line):
        while index < len(line) and line[index].isspace():
            index += 1
        if index == len(line):
            break

        token: list[str] = []
        quoted = False
        while index < len(line):
            character = line[index]
            index += 1
            if character == '"':
                quoted = not quoted
                continue
            if character == "\\":
                if index == len(line):
                    raise _fail(path, line_number, "trailing escape")
                escaped = line[index]
                index += 1
                if escaped == "x" and index + 1 < len(line):
                    high = _hex_value(line[index])
                    low = _hex_value(line[index + 1])
                    if high >= 0 and low >= 0:
                        token.append(chr((high << 4) | low))
                        index += 2
                        continue
                    token.extend(("\\", escaped))
                    continue
                decoded = {
                    "r": "\r",
                    "n": "\n",
                    "t": "\t",
                    "\\": "\\",
                    '"': '"',
                }.get(escaped)
                if decoded is None:
                    token.extend(("\\", escaped))
                else:
                    token.append(decoded)
                continue
            if not quoted and character.isspace():
                break
            token.append(character)

        if quoted:
            raise _fail(path, line_number, "unterminated quoted token")
        tokens.append("".join(token))
    return tokens


def _assignment(token: str, path: Path, line_number: int) -> tuple[str, str]:
    key, separator, value = token.partition("=")
    if not separator or not key or not value:
        raise _fail(path, line_number, f"invalid assignment: {token!r}")
    return key, value


def _parse_positive_int(
    value: str,
    path: Path,
    line_number: int,
    name: str,
    *,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise _fail(path, line_number, f"{name} must be an integer") from exc
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        suffix = "" if maximum is None else f" <= {maximum}"
        raise _fail(path, line_number, f"{name} must be > 0{suffix}")
    return parsed


def _parse_ports(value: str, path: Path, line_number: int) -> tuple[int, ...]:
    ports: set[int] = set()
    for item in value.split(","):
        if not item:
            raise _fail(path, line_number, "ports contains an empty item")
        if "-" in item:
            left_text, separator, right_text = item.partition("-")
            if not separator:
                raise _fail(path, line_number, f"invalid port range {item!r}")
            try:
                left = int(left_text, 10)
                right = int(right_text, 10)
            except ValueError as exc:
                raise _fail(path, line_number, f"invalid port range {item!r}") from exc
            if not 0 <= left <= right <= 65535:
                raise _fail(path, line_number, f"port range out of bounds: {item!r}")
            ports.update(range(left, right + 1))
        else:
            try:
                port = int(item, 10)
            except ValueError as exc:
                raise _fail(path, line_number, f"invalid port {item!r}") from exc
            if not 0 <= port <= 65535:
                raise _fail(path, line_number, f"port out of bounds: {port}")
            ports.add(port)
    return tuple(sorted(ports))


def _parse_fallbacks(value: str, path: Path, line_number: int) -> tuple[str, ...]:
    names = tuple(value.split(","))
    if not names or len(names) > _MAX_FALLBACKS:
        raise _fail(path, line_number, "invalid fallback list")
    if any(not name or _PROBE_NAME_RE.fullmatch(name) is None for name in names):
        raise _fail(path, line_number, "fallback names must be alphanumeric, '_' or '-'")
    if len(names) != len(set(names)):
        raise _fail(path, line_number, "duplicate fallback")
    return names


def _text_to_bytes(value: str, path: Path, line_number: int, name: str) -> bytes:
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise _fail(path, line_number, f"{name} contains unsupported non-byte text") from exc


def _logical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _provenance(record_id: str, logical: dict[str, Any]) -> tuple[Provenance, ...]:
    return (
        Provenance(
            source_id=_SOURCE_ID,
            source_record_id=record_id,
            source_revision=_SOURCE_REVISION,
            source_url=_SOURCE_URL,
            source_license=_SOURCE_LICENSE,
            source_hash=_logical_hash(logical),
        ),
    )


def _finish(record: CanonicalRecord) -> CanonicalRecord:
    return replace(record, id=stable_record_id(record))


def _base_record(
    *,
    kind: str,
    transport: str,
    probe_id: str,
    ports: tuple[int, ...],
    rarity: int | None,
    confidence: float | None,
    confidence_basis: str,
    provenance: tuple[Provenance, ...],
    probe_order: int,
    rule_order: int | None = None,
) -> CanonicalRecord:
    return CanonicalRecord(
        id="",
        kind=kind,
        transport=transport,
        address_family="any",
        probe_id=probe_id,
        probe_payload_ref=None,
        matcher_type=None,
        matcher_expression=None,
        service=None,
        vendor=None,
        product=None,
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=ports,
        rarity=rarity,
        confidence=confidence,
        confidence_basis=confidence_basis,
        evidence_requirements=("response",),
        negative_constraints=(),
        provenance=provenance,
        first_imported_revision=_SOURCE_REVISION,
        last_verified_revision=_SOURCE_REVISION,
        status="verified",
        notes="",
        probe_order=probe_order,
        rule_order=rule_order,
    )


def parse_service_db(path: Path) -> list[CanonicalRecord]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read {path}: {exc}") from exc

    probes: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    names: dict[str, dict[str, Any]] = {}

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        content = _without_comment(raw_line).strip()
        if not content:
            continue
        tokens = _tokenize(content, path, line_number)
        if not tokens:
            continue

        if tokens[0] == "Probe":
            if len(tokens) < 3 or tokens[1] not in {"TCP", "UDP"}:
                raise _fail(path, line_number, "Probe requires TCP|UDP and a name")
            name = tokens[2]
            if not name or any(character.isspace() for character in name):
                raise _fail(path, line_number, "invalid probe name")
            if name in names:
                raise _fail(path, line_number, f"duplicate probe {name}")

            values: dict[str, str] = {}
            for token in tokens[3:]:
                key, value = _assignment(token, path, line_number)
                if key in values:
                    raise _fail(path, line_number, f"duplicate Probe field {key}")
                if key not in {"rarity", "priority", "timeout", "ports", "fallback", "protocol"}:
                    raise _fail(path, line_number, f"unsupported Probe field {key}")
                values[key] = value

            rarity = _parse_positive_int(values.get("rarity", "1"), path, line_number, "rarity")
            priority = _parse_positive_int(values.get("priority", "50"), path, line_number, "priority", maximum=100)
            if "timeout" not in values:
                raise _fail(path, line_number, "timeout is required for lossless canonical migration")
            timeout = _parse_positive_int(values["timeout"], path, line_number, "timeout", maximum=_MAX_TIMEOUT_MS)
            ports = _parse_ports(values["ports"], path, line_number) if "ports" in values else ()
            fallbacks = _parse_fallbacks(values["fallback"], path, line_number) if "fallback" in values else ()
            transport = tokens[1].lower()
            if "protocol" in values and values["protocol"].lower() != transport:
                raise _fail(path, line_number, "protocol assignment disagrees with Probe transport")

            current = {
                "name": name,
                "transport": transport,
                "rarity": rarity,
                "priority": priority,
                "timeout": timeout,
                "ports": ports,
                "fallbacks": fallbacks,
                "payload": None,
                "rules": [],
                "line": line_number,
                "order": len(probes),
            }
            probes.append(current)
            names[name] = current
            continue

        if current is None:
            raise _fail(path, line_number, "directive appears before first Probe")

        if tokens[0] == "send":
            if len(tokens) != 2:
                raise _fail(path, line_number, "send requires exactly one quoted payload")
            if current["payload"] is not None:
                raise _fail(path, line_number, "duplicate send directive")
            current["payload"] = _text_to_bytes(tokens[1], path, line_number, "payload")
            continue

        if tokens[0] in {"match", "softmatch"}:
            values = {}
            for token in tokens[1:]:
                key, value = _assignment(token, path, line_number)
                if key in values:
                    raise _fail(path, line_number, f"duplicate match field {key}")
                if key not in {
                    "type", "pattern", "service", "product", "version", "extra", "hostname", "tunnel", "confidence"
                }:
                    raise _fail(path, line_number, f"unsupported match field {key}")
                values[key] = value
            for required in ("type", "pattern", "service", "confidence"):
                if required not in values:
                    raise _fail(path, line_number, f"match requires {required}")
            if values["type"] not in _ALLOWED_MATCH_TYPES:
                raise _fail(path, line_number, f"unsupported match type {values['type']}")
            if len(_text_to_bytes(values["pattern"], path, line_number, "pattern")) > _MAX_PATTERN_BYTES:
                raise _fail(path, line_number, "pattern is too large")
            try:
                confidence = float(values["confidence"])
            except ValueError as exc:
                raise _fail(path, line_number, "confidence must be numeric") from exc
            if not 0.0 <= confidence <= 1.0:
                raise _fail(path, line_number, "confidence must be within [0,1]")
            current["rules"].append(
                {
                    "line": line_number,
                    "order": len(current["rules"]),
                    "strength": "soft" if tokens[0] == "softmatch" else "hard",
                    "type": values["type"],
                    "pattern": values["pattern"],
                    "service": values["service"],
                    "product": values.get("product"),
                    "version": values.get("version"),
                    "extra": values.get("extra"),
                    "hostname": values.get("hostname"),
                    "tunnel": values.get("tunnel"),
                    "confidence": confidence,
                }
            )
            continue

        raise _fail(path, line_number, f"unsupported directive {tokens[0]}")

    if not probes:
        raise ValueError(f"{path.name}: database contains no probes")

    for probe in probes:
        if probe["payload"] is None:
            probe["payload"] = b""
        seen: set[str] = set()
        for fallback in probe["fallbacks"]:
            target = names.get(fallback)
            if target is None:
                raise _fail(path, probe["line"], f"fallback {fallback!r} does not reference a known probe")
            if fallback == probe["name"]:
                raise _fail(path, probe["line"], "fallback cannot reference the same probe")
            if target["transport"] != probe["transport"]:
                raise _fail(path, probe["line"], f"fallback {fallback!r} uses a different transport")
            if fallback in seen:
                raise _fail(path, probe["line"], f"duplicate fallback {fallback!r}")
            seen.add(fallback)

    records: list[CanonicalRecord] = []
    for probe in probes:
        active_logical = {
            "kind": "active_probe",
            "probe_id": probe["name"],
            "transport": probe["transport"],
            "rarity": probe["rarity"],
            "priority": probe["priority"],
            "timeout": probe["timeout"],
            "ports": list(probe["ports"]),
            "fallbacks": list(probe["fallbacks"]),
            "payload_hex": probe["payload"].hex(),
            "probe_order": probe["order"],
        }
        active = _base_record(
            kind="active_probe",
            transport=probe["transport"],
            probe_id=probe["name"],
            ports=probe["ports"],
            rarity=probe["rarity"],
            confidence=None,
            confidence_basis="first-party runtime probe",
            provenance=_provenance(f"service-probe:{probe['name']}", active_logical),
            probe_order=probe["order"],
        )
        active = replace(
            active,
            probe_payload_hex=probe["payload"].hex(),
            probe_priority=probe["priority"],
            probe_timeout_ms=probe["timeout"],
            fallback_probe_ids=probe["fallbacks"],
        )
        records.append(_finish(active))

        for rule in probe["rules"]:
            logical = {
                "kind": "service_matcher",
                "probe_id": probe["name"],
                "transport": probe["transport"],
                "ports": list(probe["ports"]),
                "rarity": probe["rarity"],
                "probe_order": probe["order"],
                **rule,
            }
            matcher = _base_record(
                kind="service_matcher",
                transport=probe["transport"],
                probe_id=probe["name"],
                ports=probe["ports"],
                rarity=probe["rarity"],
                confidence=rule["confidence"],
                confidence_basis="first-party runtime match",
                provenance=_provenance(
                    f"service-match:{probe['name']}:{rule['order']}",
                    logical,
                ),
                probe_order=probe["order"],
                rule_order=rule["order"],
            )
            matcher = replace(
                matcher,
                matcher_type=rule["type"],
                matcher_expression=rule["pattern"],
                service=rule["service"],
                product=rule["product"],
                version=rule["version"],
                match_strength=rule["strength"],
                extra_template=rule["extra"],
                hostname_template=rule["hostname"],
                tunnel_template=rule["tunnel"],
            )
            records.append(_finish(matcher))

    return records


def _quote_byte_value(data: bytes) -> str:
    pieces = ['"']
    for value in data:
        if value == 13:
            pieces.append("\\r")
        elif value == 10:
            pieces.append("\\n")
        elif value == 9:
            pieces.append("\\t")
        elif value == 92:
            pieces.append("\\\\")
        elif value == 34:
            pieces.append('\\"')
        elif 32 <= value <= 126:
            pieces.append(chr(value))
        else:
            pieces.append(f"\\x{value:02x}")
    pieces.append('"')
    return "".join(pieces)


def _quote_text(value: str) -> str:
    try:
        data = value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("runtime service text contains unsupported non-byte characters") from exc
    return _quote_byte_value(data)


def _format_confidence(value: float) -> str:
    return format(value, ".15g")


def _ordered_unique(records: list[CanonicalRecord], field: str, context: str) -> list[CanonicalRecord]:
    if any(getattr(record, field) is None for record in records):
        raise ValueError(f"{context} requires {field}")
    values = [getattr(record, field) for record in records]
    if len(values) != len(set(values)):
        raise ValueError(f"{context} contains duplicate {field}")
    ordered = sorted(records, key=lambda record: (getattr(record, field), record.id))
    if [getattr(record, field) for record in ordered] != list(range(len(ordered))):
        raise ValueError(f"{context} requires contiguous {field} starting at zero")
    return ordered


def emit_service_db(records: Iterable[CanonicalRecord]) -> str:
    record_list = list(records)
    unsupported = [record.kind for record in record_list if record.kind not in {"active_probe", "service_matcher"}]
    if unsupported:
        raise ValueError(f"service runtime emitter received unsupported kinds: {sorted(set(unsupported))}")

    probes = _ordered_unique(
        [record for record in record_list if record.kind == "active_probe"],
        "probe_order",
        "service probes",
    )
    by_name: dict[str, CanonicalRecord] = {}
    for probe in probes:
        if not probe.probe_id:
            raise ValueError("active_probe requires probe_id")
        if probe.probe_id in by_name:
            raise ValueError(f"duplicate service probe id {probe.probe_id}")
        if probe.probe_payload_hex is None or probe.probe_timeout_ms is None or probe.probe_priority is None:
            raise ValueError(f"probe {probe.probe_id} is missing payload/timeout/priority")
        by_name[probe.probe_id] = probe

    matchers_by_probe: dict[str, list[CanonicalRecord]] = {name: [] for name in by_name}
    for matcher in (record for record in record_list if record.kind == "service_matcher"):
        if matcher.probe_id not in by_name:
            raise ValueError(f"matcher references unknown probe {matcher.probe_id}")
        probe = by_name[matcher.probe_id]
        if matcher.transport != probe.transport or matcher.ports != probe.ports or matcher.rarity != probe.rarity:
            raise ValueError(f"matcher {matcher.id} disagrees with probe runtime context")
        if matcher.probe_order != probe.probe_order:
            raise ValueError(f"matcher {matcher.id} disagrees with probe_order")
        matchers_by_probe[matcher.probe_id].append(matcher)

    lines: list[str] = []
    for probe_index, probe in enumerate(probes):
        assert probe.probe_id is not None
        transport = probe.transport.upper()
        if transport not in {"TCP", "UDP"}:
            raise ValueError(f"unsupported service probe transport {probe.transport}")
        parts = [
            "Probe",
            transport,
            probe.probe_id,
            f"rarity={probe.rarity if probe.rarity is not None else 1}",
            f"priority={probe.probe_priority}",
            f"timeout={probe.probe_timeout_ms}",
        ]
        if probe.ports:
            parts.append("ports=" + ",".join(str(port) for port in probe.ports))
        if probe.fallback_probe_ids:
            for fallback in probe.fallback_probe_ids:
                target = by_name.get(fallback)
                if target is None:
                    raise ValueError(f"probe {probe.probe_id} references unknown fallback {fallback}")
                if target.transport != probe.transport:
                    raise ValueError(f"probe {probe.probe_id} fallback {fallback} uses a different transport")
            parts.append("fallback=" + ",".join(probe.fallback_probe_ids))
        lines.append(" ".join(parts))
        try:
            payload = bytes.fromhex(probe.probe_payload_hex)
        except ValueError as exc:
            raise ValueError(f"probe {probe.probe_id} has invalid payload hex") from exc
        lines.append("send " + _quote_byte_value(payload))

        matchers = _ordered_unique(matchers_by_probe[probe.probe_id], "rule_order", f"rules for {probe.probe_id}")
        for matcher in matchers:
            if (
                matcher.matcher_type not in _ALLOWED_MATCH_TYPES
                or matcher.matcher_expression is None
                or matcher.service is None
                or matcher.match_strength not in {"hard", "soft"}
                or matcher.confidence is None
            ):
                raise ValueError(f"matcher {matcher.id} is incomplete")
            directive = "softmatch" if matcher.match_strength == "soft" else "match"
            rule_parts = [
                directive,
                f"type={matcher.matcher_type}",
                "pattern=" + _quote_text(matcher.matcher_expression),
                "service=" + _quote_text(matcher.service),
            ]
            for key, value in (
                ("product", matcher.product),
                ("version", matcher.version),
                ("extra", matcher.extra_template),
                ("hostname", matcher.hostname_template),
                ("tunnel", matcher.tunnel_template),
            ):
                if value is not None:
                    rule_parts.append(f"{key}=" + _quote_text(value))
            rule_parts.append("confidence=" + _format_confidence(matcher.confidence))
            lines.append(" ".join(rule_parts))

        if probe_index + 1 < len(probes):
            lines.append("")

    return "\n".join(lines) + ("\n" if lines else "")
