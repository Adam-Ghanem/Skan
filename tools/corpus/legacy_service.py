from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
from pathlib import Path
from typing import Iterable, Mapping

from tools.corpus.model import (
    ActiveProbeSemantics,
    CanonicalRecord,
    CanonicalRecordError,
    SCHEMA_VERSION,
    ServiceMatcherSemantics,
    parse_record,
    record_to_mapping,
    stable_record_id,
)
from tools.corpus.sources import SourcePolicy


_MAXIMUM_DATABASE_BYTES = 1 << 20
_MAXIMUM_LINE_BYTES = 16 << 10
_MAXIMUM_PROBES = 256
_MAXIMUM_RULES_PER_PROBE = 256
_MAXIMUM_PATTERN_BYTES = 4096
_MAXIMUM_REGEX_BYTES = 512
_MAXIMUM_ACTIVE_PAYLOAD_BYTES = 4000
_MAXIMUM_PORTS = 256
_MAXIMUM_FALLBACKS = 16
_MAXIMUM_TIMEOUT_MS = 60000
_MAXIMUM_UNSIGNED = (1 << 32) - 1
_ASCII_SPACE = frozenset(b" \t\n\r\v\f")
_MATCH_TYPES = {"exact", "prefix", "suffix", "substring", "regex"}
_METADATA_KEYS = {"product", "version", "extra", "hostname", "tunnel"}


class LegacyServiceError(ValueError):
    """The legacy service corpus cannot be migrated or compiled losslessly."""


@dataclass
class _RuleDraft:
    matcher_type: str = "prefix"
    pattern: bytes | None = None
    strength: str = "hard"
    service: str | None = None
    product: str | None = None
    version_template: str | None = None
    extra: str | None = None
    hostname_template: str | None = None
    tunnel: str | None = None
    confidence: float | None = None
    source_content: bytes = b""


@dataclass
class _ProbeDraft:
    name: str
    transport: str
    declaration_order: int
    header_content: bytes
    rarity: int = 1
    priority: int = 50
    timeout_ms: int | None = None
    ports: tuple[int, ...] = ()
    fallback_probe_names: tuple[str, ...] = ()
    payload: bytes = b""
    send_seen: bool = False
    send_content: bytes | None = None
    rules: list[_RuleDraft] = field(default_factory=list)


def _source_policy(
    sources: Mapping[str, SourcePolicy], source_id: str, kind: str
) -> SourcePolicy:
    source = sources.get(source_id)
    if source is None:
        raise LegacyServiceError(f"unknown source_id: {source_id}")
    if kind not in source.approved_data_classes or kind in source.blocked_data_classes:
        raise LegacyServiceError(f"source is not authorized for {kind}: {source_id}")
    return source


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _is_space(value: int) -> bool:
    return value in _ASCII_SPACE


def _trim(value: bytes) -> bytes:
    start = 0
    end = len(value)
    while start < end and _is_space(value[start]):
        start += 1
    while end > start and _is_space(value[end - 1]):
        end -= 1
    return value[start:end]


def _without_comment(value: bytes) -> bytes:
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted and character == ord("\\"):
            escaped = True
            continue
        if character == ord('"'):
            quoted = not quoted
        elif not quoted and character == ord("#"):
            return value[:index]
    return value


def _hexadecimal_value(value: int) -> int:
    if ord("0") <= value <= ord("9"):
        return value - ord("0")
    if ord("a") <= value <= ord("f"):
        return value - ord("a") + 10
    if ord("A") <= value <= ord("F"):
        return value - ord("A") + 10
    return -1


def _tokenize(value: bytes, line_number: int) -> tuple[bytes, ...]:
    tokens: list[bytes] = []
    index = 0
    while index < len(value):
        while index < len(value) and _is_space(value[index]):
            index += 1
        if index == len(value):
            break

        token = bytearray()
        quoted = False
        while index < len(value):
            character = value[index]
            index += 1
            if character == ord('"'):
                quoted = not quoted
                continue
            if character == ord("\\"):
                if index == len(value):
                    raise LegacyServiceError(f"line {line_number}: dangling escape")
                escaped = value[index]
                index += 1
                if escaped == ord("x") and index + 1 < len(value):
                    high = _hexadecimal_value(value[index])
                    low = _hexadecimal_value(value[index + 1])
                    if high >= 0 and low >= 0:
                        token.append((high << 4) | low)
                        index += 2
                        continue
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
                continue
            if not quoted and _is_space(character):
                break
            token.append(character)
        if quoted:
            raise LegacyServiceError(f"line {line_number}: unterminated quote")
        tokens.append(bytes(token))
    return tuple(tokens)


def _ascii(value: bytes, field_name: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LegacyServiceError(f"{field_name} must be ASCII") from exc


def _utf8(value: bytes, field_name: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyServiceError(f"{field_name} must be valid UTF-8") from exc


def _split_assignment(token: bytes, line_number: int) -> tuple[str, bytes]:
    equal = token.find(b"=")
    if equal <= 0 or equal == len(token) - 1:
        raise LegacyServiceError(f"line {line_number}: expected key=value assignment")
    key = _ascii(token[:equal], f"line {line_number} assignment key")
    return key, token[equal + 1 :]


def _parse_unsigned(
    value: bytes,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = _MAXIMUM_UNSIGNED,
) -> int:
    text = _ascii(value, field_name)
    if not text or any(character < "0" or character > "9" for character in text):
        raise LegacyServiceError(f"{field_name} must be an unsigned decimal integer")
    parsed = int(text, 10)
    if not minimum <= parsed <= maximum:
        raise LegacyServiceError(f"{field_name} must be in range {minimum}..{maximum}")
    return parsed


def _parse_confidence(value: bytes, field_name: str) -> float:
    text = _ascii(value, field_name)
    try:
        parsed = float(text)
    except ValueError as exc:
        raise LegacyServiceError(f"{field_name} must be a decimal number") from exc
    if not math.isfinite(parsed) or not 0.0 <= parsed <= 1.0:
        raise LegacyServiceError(f"{field_name} must be within 0.0..1.0")
    return parsed


def _parse_ports(value: bytes, field_name: str) -> tuple[int, ...]:
    text = _ascii(value, field_name)
    if not text.strip():
        raise LegacyServiceError(f"{field_name} must not be empty")
    ports: list[int] = []
    for raw_token in text.split(","):
        token = raw_token.strip()
        if not token:
            raise LegacyServiceError(f"{field_name} contains an empty port token")
        if "-" not in token:
            ports.append(
                _parse_unsigned(
                    token.encode("ascii"), field_name, minimum=1, maximum=65535
                )
            )
        else:
            if token.count("-") != 1:
                raise LegacyServiceError(f"{field_name} contains an invalid range")
            first_text, last_text = token.split("-", 1)
            first = _parse_unsigned(
                first_text.encode("ascii"), field_name, minimum=1, maximum=65535
            )
            last = _parse_unsigned(
                last_text.encode("ascii"), field_name, minimum=1, maximum=65535
            )
            if first > last:
                raise LegacyServiceError(f"{field_name} range minimum exceeds maximum")
            if last - first + 1 > _MAXIMUM_PORTS:
                raise LegacyServiceError(f"{field_name} expands beyond {_MAXIMUM_PORTS} ports")
            ports.extend(range(first, last + 1))
        if len(set(ports)) > _MAXIMUM_PORTS:
            raise LegacyServiceError(f"{field_name} exceeds {_MAXIMUM_PORTS} ports")
    return tuple(sorted(set(ports)))


def _parse_fallbacks(value: bytes, field_name: str) -> tuple[str, ...]:
    names: list[str] = []
    for raw_name in value.split(b","):
        name = _ascii(raw_name, field_name)
        if (
            not name
            or len(names) >= _MAXIMUM_FALLBACKS
            or any(not (character.isalnum() or character in "_-") for character in name)
        ):
            raise LegacyServiceError(f"{field_name} contains an invalid fallback probe name")
        names.append(name)
    if len(names) != len(set(names)):
        raise LegacyServiceError(f"{field_name} contains duplicate fallback names")
    return tuple(names)


def _regex_is_bounded(pattern: bytes) -> bool:
    if len(pattern) > _MAXIMUM_REGEX_BYTES:
        return False
    captures = 0
    escaped = False
    for index, character in enumerate(pattern):
        if escaped:
            if ord("1") <= character <= ord("9"):
                return False
            escaped = False
            continue
        if character == ord("\\"):
            escaped = True
            continue
        if character == ord("("):
            captures += 1
            if captures > 16:
                return False
        if character in (ord("*"), ord("+")) and index + 2 < len(pattern):
            if pattern[index + 1] == ord(")") and pattern[index + 2] in (
                ord("*"),
                ord("+"),
                ord("{"),
            ):
                return False
    return not escaped


def _provenance(
    source: SourcePolicy,
    source_record_id: str,
    contribution: bytes,
) -> list[dict[str, object]]:
    return [
        {
            "source_id": source.id,
            "source_record_id": source_record_id,
            "source_revision": source.pinned_revision,
            "source_url": source.source_url,
            "source_license": source.license_spdx_or_policy,
            "snapshot_hash": source.expected_hash,
            "record_hash": _sha256(contribution),
        }
    ]


def _canonical_active(
    probe: _ProbeDraft,
    source: SourcePolicy,
    sources: Mapping[str, SourcePolicy],
) -> CanonicalRecord:
    contribution = probe.header_content
    if probe.send_content is not None:
        contribution += b"\n" + probe.send_content
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "kind": "active_probe",
        "body": {
            "probe_name": probe.name,
            "transport": probe.transport,
            "payload_hex": probe.payload.hex(),
            "rarity": probe.rarity,
            "priority": probe.priority,
            "timeout_ms": probe.timeout_ms,
            "ports": list(probe.ports),
            "fallback_probe_names": list(probe.fallback_probe_names),
            "declaration_order": probe.declaration_order,
        },
        "provenance": _provenance(
            source, f"service-probe:{probe.name}", contribution
        ),
        "first_imported_revision": source.pinned_revision,
        "last_verified_revision": source.pinned_revision,
        "status": "imported",
        "notes": "Deterministically migrated from the Skan legacy service runtime corpus.",
    }
    try:
        value["id"] = stable_record_id(value)
        return parse_record(value, sources)
    except CanonicalRecordError as exc:
        raise LegacyServiceError(str(exc)) from exc


def _canonical_matcher(
    probe: _ProbeDraft,
    rule: _RuleDraft,
    rule_order: int,
    source: SourcePolicy,
    sources: Mapping[str, SourcePolicy],
) -> CanonicalRecord:
    assert rule.pattern is not None
    assert rule.service is not None
    assert rule.confidence is not None
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "kind": "service_matcher",
        "body": {
            "probe_name": probe.name,
            "matcher_type": rule.matcher_type,
            "pattern": None,
            "pattern_hex": rule.pattern.hex(),
            "strength": rule.strength,
            "service": rule.service,
            "product": rule.product,
            "version_template": rule.version_template,
            "extra": rule.extra,
            "hostname_template": rule.hostname_template,
            "tunnel": rule.tunnel,
            "confidence": rule.confidence,
            "rule_order": rule_order,
            "cpe": [],
        },
        "provenance": _provenance(
            source, f"service-match:{probe.name}:{rule_order}", rule.source_content
        ),
        "first_imported_revision": source.pinned_revision,
        "last_verified_revision": source.pinned_revision,
        "status": "imported",
        "notes": "Deterministically migrated from the Skan legacy service runtime corpus.",
    }
    try:
        value["id"] = stable_record_id(value)
        return parse_record(value, sources)
    except CanonicalRecordError as exc:
        raise LegacyServiceError(str(exc)) from exc


def _parse_legacy_service_bytes(
    raw_bytes: bytes,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str,
) -> tuple[CanonicalRecord, ...]:
    if len(raw_bytes) > _MAXIMUM_DATABASE_BYTES:
        raise LegacyServiceError(
            f"legacy service corpus exceeds {_MAXIMUM_DATABASE_BYTES} bytes"
        )
    active_source = _source_policy(sources, source_id, "active_probe")
    matcher_source = _source_policy(sources, source_id, "service_matcher")
    if active_source != matcher_source:
        raise LegacyServiceError("active probe and matcher source policies must be identical")
    source = active_source

    probes: list[_ProbeDraft] = []
    names: set[str] = set()
    current: _ProbeDraft | None = None

    for line_number, raw_line in enumerate(raw_bytes.splitlines(), start=1):
        if len(raw_line) > _MAXIMUM_LINE_BYTES:
            raise LegacyServiceError(
                f"line {line_number} exceeds {_MAXIMUM_LINE_BYTES} bytes"
            )
        content = _trim(_without_comment(raw_line))
        if not content:
            continue
        tokens = _tokenize(content, line_number)
        if not tokens:
            continue
        keyword = _ascii(tokens[0], f"line {line_number} keyword")

        if keyword == "Probe":
            if len(tokens) < 3:
                raise LegacyServiceError(f"line {line_number}: incomplete Probe declaration")
            if len(probes) >= _MAXIMUM_PROBES:
                raise LegacyServiceError(f"probe count exceeds {_MAXIMUM_PROBES}")
            protocol = _ascii(tokens[1], f"line {line_number} transport")
            if protocol not in {"TCP", "UDP"}:
                raise LegacyServiceError(f"line {line_number}: unsupported transport")
            name = _ascii(tokens[2], f"line {line_number} probe name")
            if not name:
                raise LegacyServiceError(f"line {line_number}: probe name is required")
            if name in names:
                raise LegacyServiceError(f"line {line_number}: duplicate probe name: {name}")
            names.add(name)
            current = _ProbeDraft(
                name=name,
                transport=protocol.lower(),
                declaration_order=len(probes),
                header_content=content,
            )
            seen: set[str] = set()
            for token in tokens[3:]:
                key, raw_value = _split_assignment(token, line_number)
                if key in seen:
                    raise LegacyServiceError(
                        f"line {line_number}: duplicate Probe assignment: {key}"
                    )
                seen.add(key)
                if key == "rarity":
                    current.rarity = _parse_unsigned(
                        raw_value,
                        f"line {line_number} rarity",
                        minimum=1,
                    )
                elif key == "priority":
                    current.priority = _parse_unsigned(
                        raw_value,
                        f"line {line_number} priority",
                        minimum=1,
                        maximum=100,
                    )
                elif key == "timeout":
                    current.timeout_ms = _parse_unsigned(
                        raw_value,
                        f"line {line_number} timeout",
                        minimum=1,
                        maximum=_MAXIMUM_TIMEOUT_MS,
                    )
                elif key == "ports":
                    current.ports = _parse_ports(
                        raw_value, f"line {line_number} ports"
                    )
                elif key == "fallback":
                    current.fallback_probe_names = _parse_fallbacks(
                        raw_value, f"line {line_number} fallback"
                    )
                elif key == "protocol":
                    expected = current.transport
                    actual = _ascii(raw_value, f"line {line_number} protocol")
                    if actual != expected:
                        raise LegacyServiceError(
                            f"line {line_number}: protocol assignment does not match transport"
                        )
                else:
                    raise LegacyServiceError(
                        f"line {line_number}: unsupported Probe assignment: {key}"
                    )
            probes.append(current)
            continue

        if keyword == "send":
            if current is None or len(tokens) != 2:
                raise LegacyServiceError(f"line {line_number}: invalid send declaration")
            if current.send_seen:
                raise LegacyServiceError(
                    f"line {line_number}: duplicate send declaration for {current.name}"
                )
            if len(tokens[1]) > _MAXIMUM_ACTIVE_PAYLOAD_BYTES:
                raise LegacyServiceError(
                    f"line {line_number}: send payload exceeds {_MAXIMUM_ACTIVE_PAYLOAD_BYTES} bytes"
                )
            current.payload = tokens[1]
            current.send_seen = True
            current.send_content = content
            continue

        if keyword in {"match", "softmatch"}:
            if current is None:
                raise LegacyServiceError(f"line {line_number}: matcher has no owning probe")
            if len(current.rules) >= _MAXIMUM_RULES_PER_PROBE:
                raise LegacyServiceError(
                    f"line {line_number}: rule count exceeds {_MAXIMUM_RULES_PER_PROBE}"
                )
            rule = _RuleDraft(
                strength="soft" if keyword == "softmatch" else "hard",
                source_content=content,
            )
            seen: set[str] = set()
            for token in tokens[1:]:
                key, raw_value = _split_assignment(token, line_number)
                if key in seen:
                    raise LegacyServiceError(
                        f"line {line_number}: duplicate matcher assignment: {key}"
                    )
                seen.add(key)
                if key == "type":
                    matcher_type = _ascii(raw_value, f"line {line_number} matcher type")
                    if matcher_type not in _MATCH_TYPES:
                        raise LegacyServiceError(
                            f"line {line_number}: unsupported matcher type"
                        )
                    rule.matcher_type = matcher_type
                elif key == "pattern":
                    if len(raw_value) > _MAXIMUM_PATTERN_BYTES:
                        raise LegacyServiceError(
                            f"line {line_number}: pattern exceeds {_MAXIMUM_PATTERN_BYTES} bytes"
                        )
                    rule.pattern = raw_value
                elif key == "service":
                    rule.service = _utf8(raw_value, f"line {line_number} service")
                elif key in _METADATA_KEYS:
                    text = _utf8(raw_value, f"line {line_number} {key}")
                    if key == "product":
                        rule.product = text
                    elif key == "version":
                        rule.version_template = text
                    elif key == "extra":
                        rule.extra = text
                    elif key == "hostname":
                        rule.hostname_template = text
                    else:
                        rule.tunnel = text
                elif key == "confidence":
                    rule.confidence = _parse_confidence(
                        raw_value, f"line {line_number} confidence"
                    )
                else:
                    raise LegacyServiceError(
                        f"line {line_number}: unsupported matcher assignment: {key}"
                    )
            if rule.pattern is None:
                raise LegacyServiceError(f"line {line_number}: pattern is required")
            if rule.service is None:
                raise LegacyServiceError(f"line {line_number}: service is required")
            if rule.confidence is None:
                raise LegacyServiceError(f"line {line_number}: confidence is required")
            if rule.matcher_type == "regex":
                if len(rule.pattern) > _MAXIMUM_REGEX_BYTES:
                    raise LegacyServiceError(
                        f"line {line_number}: regex exceeds {_MAXIMUM_REGEX_BYTES} bytes"
                    )
                if not _regex_is_bounded(rule.pattern):
                    raise LegacyServiceError(
                        f"line {line_number}: regex violates runtime bounded-regex policy"
                    )
            current.rules.append(rule)
            continue

        raise LegacyServiceError(f"line {line_number}: unsupported directive: {keyword}")

    if not probes:
        raise LegacyServiceError("legacy service corpus contains no probes")

    by_name = {probe.name: probe for probe in probes}
    for probe in probes:
        seen_fallbacks: set[str] = set()
        for fallback_name in probe.fallback_probe_names:
            fallback = by_name.get(fallback_name)
            if fallback is None:
                raise LegacyServiceError(
                    f"probe {probe.name}: unknown fallback: {fallback_name}"
                )
            if fallback_name == probe.name:
                raise LegacyServiceError(f"probe {probe.name}: fallback cannot reference itself")
            if fallback.transport != probe.transport:
                raise LegacyServiceError(
                    f"probe {probe.name}: fallback transport differs: {fallback_name}"
                )
            if fallback_name in seen_fallbacks:
                raise LegacyServiceError(
                    f"probe {probe.name}: duplicate fallback: {fallback_name}"
                )
            seen_fallbacks.add(fallback_name)

    records: list[CanonicalRecord] = []
    for probe in probes:
        records.append(_canonical_active(probe, source, sources))
        for rule_order, rule in enumerate(probe.rules):
            records.append(
                _canonical_matcher(probe, rule, rule_order, source, sources)
            )
    return tuple(records)


def parse_legacy_service(
    text: str,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    try:
        raw_bytes = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LegacyServiceError("legacy service corpus must be valid UTF-8 text") from exc
    return _parse_legacy_service_bytes(raw_bytes, sources, source_id=source_id)


def load_legacy_service(
    path: Path,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise LegacyServiceError(f"cannot read legacy service corpus: {exc}") from exc
    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyServiceError("legacy service corpus must be valid UTF-8") from exc
    return _parse_legacy_service_bytes(raw_bytes, sources, source_id=source_id)


def _validated_records(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
) -> tuple[tuple[CanonicalRecord, ...], tuple[CanonicalRecord, ...]]:
    active: list[CanonicalRecord] = []
    matchers: list[CanonicalRecord] = []
    for record in records:
        if not isinstance(record, CanonicalRecord):
            raise LegacyServiceError("compiler input must contain CanonicalRecord values")
        try:
            checked = parse_record(record_to_mapping(record), sources)
        except CanonicalRecordError as exc:
            raise LegacyServiceError(str(exc)) from exc
        if checked.kind == "active_probe":
            if not isinstance(checked.body, ActiveProbeSemantics):
                raise LegacyServiceError("active_probe record has incompatible body")
            active.append(checked)
        elif checked.kind == "service_matcher":
            if not isinstance(checked.body, ServiceMatcherSemantics):
                raise LegacyServiceError("service_matcher record has incompatible body")
            matchers.append(checked)
        else:
            raise LegacyServiceError(
                "service compiler accepts only active_probe and service_matcher records"
            )
    if not active:
        raise LegacyServiceError("service compiler requires at least one active probe")
    return tuple(active), tuple(matchers)


def _validated_service_graph(
    active: tuple[CanonicalRecord, ...],
    matchers: tuple[CanonicalRecord, ...],
) -> tuple[tuple[CanonicalRecord, ...], dict[str, tuple[CanonicalRecord, ...]]]:
    ordered_active = tuple(
        sorted(active, key=lambda record: record.body.declaration_order)  # type: ignore[union-attr]
    )
    orders = tuple(
        record.body.declaration_order for record in ordered_active  # type: ignore[union-attr]
    )
    if orders != tuple(range(len(ordered_active))):
        raise LegacyServiceError("active probe declaration_order must be contiguous from zero")
    if len(ordered_active) > _MAXIMUM_PROBES:
        raise LegacyServiceError(f"probe count exceeds {_MAXIMUM_PROBES}")

    by_name: dict[str, CanonicalRecord] = {}
    for record in ordered_active:
        body = record.body
        assert isinstance(body, ActiveProbeSemantics)
        if body.probe_name in by_name:
            raise LegacyServiceError(f"duplicate probe name: {body.probe_name}")
        by_name[body.probe_name] = record

    for record in ordered_active:
        body = record.body
        assert isinstance(body, ActiveProbeSemantics)
        for fallback_name in body.fallback_probe_names:
            fallback_record = by_name.get(fallback_name)
            if fallback_record is None:
                raise LegacyServiceError(
                    f"probe {body.probe_name}: unknown fallback: {fallback_name}"
                )
            fallback_body = fallback_record.body
            assert isinstance(fallback_body, ActiveProbeSemantics)
            if fallback_name == body.probe_name:
                raise LegacyServiceError(
                    f"probe {body.probe_name}: fallback cannot reference itself"
                )
            if fallback_body.transport != body.transport:
                raise LegacyServiceError(
                    f"probe {body.probe_name}: fallback transport differs: {fallback_name}"
                )

    grouped: dict[str, list[CanonicalRecord]] = {name: [] for name in by_name}
    for record in matchers:
        body = record.body
        assert isinstance(body, ServiceMatcherSemantics)
        if body.probe_name not in by_name:
            raise LegacyServiceError(
                f"matcher references unknown probe: {body.probe_name}"
            )
        if body.cpe:
            raise LegacyServiceError(
                "current service runtime grammar cannot represent CPE metadata"
            )
        grouped[body.probe_name].append(record)

    ordered_matchers: dict[str, tuple[CanonicalRecord, ...]] = {}
    for probe_name, group in grouped.items():
        ordered = tuple(
            sorted(group, key=lambda record: record.body.rule_order)  # type: ignore[union-attr]
        )
        orders = tuple(
            record.body.rule_order for record in ordered  # type: ignore[union-attr]
        )
        if orders != tuple(range(len(ordered))):
            raise LegacyServiceError(
                f"probe {probe_name}: rule_order must be contiguous from zero"
            )
        if len(ordered) > _MAXIMUM_RULES_PER_PROBE:
            raise LegacyServiceError(
                f"probe {probe_name}: rule count exceeds {_MAXIMUM_RULES_PER_PROBE}"
            )
        for record in ordered:
            body = record.body
            assert isinstance(body, ServiceMatcherSemantics)
            if body.pattern_hex is None:
                raise LegacyServiceError("matcher pattern must be canonicalized to pattern_hex")
            pattern = bytes.fromhex(body.pattern_hex)
            if body.matcher_type == "regex" and not _regex_is_bounded(pattern):
                raise LegacyServiceError(
                    f"probe {probe_name}: regex violates runtime bounded-regex policy"
                )
        ordered_matchers[probe_name] = ordered
    return ordered_active, ordered_matchers


def _escape_runtime_bytes(value: bytes) -> str:
    output = ['"']
    for byte in value:
        if byte == ord("\r"):
            output.append("\\r")
        elif byte == ord("\n"):
            output.append("\\n")
        elif byte == ord("\t"):
            output.append("\\t")
        elif byte == ord("\\"):
            output.append("\\\\")
        elif byte == ord('"'):
            output.append('\\"')
        elif 0x20 <= byte <= 0x7E:
            output.append(chr(byte))
        else:
            output.append(f"\\x{byte:02x}")
    output.append('"')
    return "".join(output)


def _assignment(key: str, value: str) -> str:
    return f"{key}={_escape_runtime_bytes(value.encode('utf-8'))}"


def compile_legacy_service(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
) -> str:
    active, matchers = _validated_records(records, sources)
    ordered_active, grouped = _validated_service_graph(active, matchers)

    lines = [
        "# Generated from Skan Intelligence Database v2 canonical service records.",
        "# Runtime authority remains the existing ServiceProbeDatabase grammar.",
    ]
    for record in ordered_active:
        body = record.body
        assert isinstance(body, ActiveProbeSemantics)
        header = [
            "Probe",
            body.transport.upper(),
            body.probe_name,
            f"rarity={body.rarity}",
            f"priority={body.priority}",
        ]
        if body.timeout_ms is not None:
            header.append(f"timeout={body.timeout_ms}")
        if body.ports:
            header.append("ports=" + ",".join(str(port) for port in body.ports))
        if body.fallback_probe_names:
            header.append("fallback=" + ",".join(body.fallback_probe_names))
        header_line = " ".join(header)
        if len(header_line.encode("utf-8")) > _MAXIMUM_LINE_BYTES:
            raise LegacyServiceError("generated Probe line exceeds runtime line bound")
        lines.append(header_line)

        payload_line = "send " + _escape_runtime_bytes(bytes.fromhex(body.payload_hex))
        if len(payload_line.encode("utf-8")) > _MAXIMUM_LINE_BYTES:
            raise LegacyServiceError("generated send line exceeds runtime line bound")
        lines.append(payload_line)

        for matcher_record in grouped[body.probe_name]:
            matcher = matcher_record.body
            assert isinstance(matcher, ServiceMatcherSemantics)
            assert matcher.pattern_hex is not None
            prefix = "softmatch" if matcher.strength == "soft" else "match"
            parts = [
                prefix,
                f"type={matcher.matcher_type}",
                "pattern=" + _escape_runtime_bytes(bytes.fromhex(matcher.pattern_hex)),
                _assignment("service", matcher.service),
            ]
            if matcher.product is not None:
                parts.append(_assignment("product", matcher.product))
            if matcher.version_template is not None:
                parts.append(_assignment("version", matcher.version_template))
            if matcher.extra is not None:
                parts.append(_assignment("extra", matcher.extra))
            if matcher.hostname_template is not None:
                parts.append(_assignment("hostname", matcher.hostname_template))
            if matcher.tunnel is not None:
                parts.append(_assignment("tunnel", matcher.tunnel))
            parts.append(f"confidence={matcher.confidence!r}")
            rule_line = " ".join(parts)
            if len(rule_line.encode("utf-8")) > _MAXIMUM_LINE_BYTES:
                raise LegacyServiceError("generated matcher line exceeds runtime line bound")
            lines.append(rule_line)
        lines.append("")

    generated = "\n".join(lines).rstrip() + "\n"
    if len(generated.encode("utf-8")) > _MAXIMUM_DATABASE_BYTES:
        raise LegacyServiceError("generated service corpus exceeds runtime database bound")
    return generated


def semantic_service_ids(records: Iterable[CanonicalRecord]) -> tuple[str, ...]:
    collected = tuple(records)
    active = tuple(record for record in collected if record.kind == "active_probe")
    matchers = tuple(record for record in collected if record.kind == "service_matcher")
    if len(active) + len(matchers) != len(collected):
        raise LegacyServiceError(
            "semantic service comparison accepts only active_probe and service_matcher records"
        )
    ordered_active, grouped = _validated_service_graph(active, matchers)
    identifiers: list[str] = []
    for record in ordered_active:
        body = record.body
        assert isinstance(body, ActiveProbeSemantics)
        identifiers.append(record.id)
        identifiers.extend(item.id for item in grouped[body.probe_name])
    return tuple(identifiers)


def verify_service_round_trip(
    expected: Iterable[CanonicalRecord],
    actual: Iterable[CanonicalRecord],
) -> None:
    if semantic_service_ids(expected) != semantic_service_ids(actual):
        raise LegacyServiceError("service semantic round-trip mismatch")
