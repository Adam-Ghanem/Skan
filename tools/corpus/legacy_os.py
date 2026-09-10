from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from typing import Iterable, Mapping

from tools.corpus.model import (
    CanonicalRecord,
    CanonicalRecordError,
    OSFingerprintSemantics,
    OSSignature,
    SCHEMA_VERSION,
    parse_record,
    record_to_mapping,
    stable_record_id,
)
from tools.corpus.sources import SourcePolicy


_MAXIMUM_DATABASE_BYTES = 1 << 20
_MAXIMUM_LINE_BYTES = 4096
_MAXIMUM_FINGERPRINTS = 256
_MAXIMUM_SIGNATURES = 64
_MAXIMUM_STRING_BYTES = 128
_MAXIMUM_INT64 = (1 << 63) - 1

_FIELD_SPECS: dict[str, tuple[str, str]] = {
    "TTL": ("ttl", "eq"),
    "TTL_RANGE": ("ttl", "range"),
    "DF": ("dont_fragment", "bool"),
    "WINDOW": ("window", "eq"),
    "WINDOW_RANGE": ("window", "range"),
    "MSS": ("mss", "eq"),
    "WSCALE": ("window_scale", "eq"),
    "SACK": ("sack_permitted", "bool"),
    "TIMESTAMP": ("timestamps", "bool"),
    "TCP_OPTIONS": ("tcp_options", "tcp_options"),
    "TCP_FLAGS": ("tcp_flags", "eq"),
    "ACK_BEHAVIOR": ("ack_behavior", "text"),
    "SEQUENCE_BEHAVIOR": ("sequence_behavior", "text"),
    "RESPONSE_BEHAVIOR": ("response_behavior", "text"),
    "ICMP_TTL": ("icmp_ttl", "eq"),
    "ICMP_TTL_RANGE": ("icmp_ttl", "range"),
    "ICMP_TYPE": ("icmp_type", "eq"),
    "ICMP_CODE": ("icmp_code", "eq"),
    "UDP_PAYLOAD_LENGTH": ("udp_payload_length", "eq"),
    "UDP_PAYLOAD_RANGE": ("udp_payload_length", "range"),
    "UDP_RESPONSE_BEHAVIOR": ("udp_response_behavior", "text"),
    "RESPONSE_PRESENCE": ("response_presence", "bool"),
}

_CANONICAL_FIELD_NAMES: dict[str, str] = {
    "ttl": "TTL",
    "dont_fragment": "DF",
    "window": "WINDOW",
    "mss": "MSS",
    "window_scale": "WSCALE",
    "sack_permitted": "SACK",
    "timestamps": "TIMESTAMP",
    "tcp_options": "TCP_OPTIONS",
    "tcp_flags": "TCP_FLAGS",
    "ack_behavior": "ACK_BEHAVIOR",
    "sequence_behavior": "SEQUENCE_BEHAVIOR",
    "response_behavior": "RESPONSE_BEHAVIOR",
    "icmp_ttl": "ICMP_TTL",
    "icmp_type": "ICMP_TYPE",
    "icmp_code": "ICMP_CODE",
    "udp_payload_length": "UDP_PAYLOAD_LENGTH",
    "udp_response_behavior": "UDP_RESPONSE_BEHAVIOR",
    "response_presence": "RESPONSE_PRESENCE",
}

_RANGE_FIELD_NAMES: dict[str, str] = {
    "ttl": "TTL_RANGE",
    "window": "WINDOW_RANGE",
    "icmp_ttl": "ICMP_TTL_RANGE",
    "udp_payload_length": "UDP_PAYLOAD_RANGE",
}

_OPTION_ALIASES = {
    "NOP": "NOP",
    "MSS": "MSS",
    "WS": "WS",
    "WSCALE": "WS",
    "SACK": "SACK",
    "TS": "TS",
    "TIMESTAMP": "TS",
}


class LegacyOSError(ValueError):
    """The legacy OS corpus cannot be migrated or compiled losslessly."""


@dataclass
class _FingerprintDraft:
    name: str
    expected_family: str
    source_lines: list[str] = field(default_factory=list)
    runtime_id: str | None = None
    specificity: int | None = None
    address_family: str | None = None
    vendor: str | None = None
    os_family: str | None = None
    os_generation: str = ""
    device_type: str = ""
    signatures: list[OSSignature] = field(default_factory=list)
    signature_fields: set[str] = field(default_factory=set)
    id_seen: bool = False
    specificity_seen: bool = False
    family_seen: bool = False
    class_seen: bool = False


def _source_policy(
    sources: Mapping[str, SourcePolicy], source_id: str
) -> SourcePolicy:
    source = sources.get(source_id)
    if source is None:
        raise LegacyOSError(f"unknown source_id: {source_id}")
    if (
        "os_fingerprint" not in source.approved_data_classes
        or "os_fingerprint" in source.blocked_data_classes
    ):
        raise LegacyOSError(f"source is not authorized for os_fingerprint: {source_id}")
    return source


def _record_hash(lines: Iterable[str]) -> str:
    normalized = "\n".join(lines) + "\n"
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _semantic_line(raw_line: str) -> str:
    return raw_line.split("#", 1)[0].strip(" \t\r")


def _parse_unsigned(value: str, context: str, *, maximum: int = _MAXIMUM_INT64) -> int:
    if not value or any(character < "0" or character > "9" for character in value):
        raise LegacyOSError(f"{context} must be an unsigned decimal integer")
    parsed = int(value, 10)
    if parsed > maximum:
        raise LegacyOSError(f"{context} exceeds {maximum}")
    return parsed


def _parse_range(value: str, context: str) -> tuple[int, int]:
    if value.count("-") != 1:
        raise LegacyOSError(f"{context} must be MIN-MAX")
    minimum_text, maximum_text = value.split("-", 1)
    minimum = _parse_unsigned(minimum_text.strip(), f"{context} minimum")
    maximum = _parse_unsigned(maximum_text.strip(), f"{context} maximum")
    if minimum > maximum:
        raise LegacyOSError(f"{context} minimum must not exceed maximum")
    return minimum, maximum


def _parse_boolean(value: str, context: str) -> bool:
    if value in {"Y", "YES", "1"}:
        return True
    if value in {"N", "NO", "0"}:
        return False
    raise LegacyOSError(f"{context} must be Y/YES/1 or N/NO/0")


def _parse_options(value: str, context: str) -> tuple[str, ...]:
    raw_options = [item.strip() for item in value.split(",")]
    if not raw_options or any(not item for item in raw_options):
        raise LegacyOSError(f"{context} must contain non-empty TCP options")
    options: list[str] = []
    for option in raw_options:
        canonical = _OPTION_ALIASES.get(option)
        if canonical is None:
            raise LegacyOSError(f"{context} contains unsupported TCP option: {option}")
        options.append(canonical)
    if len(options) > _MAXIMUM_SIGNATURES:
        raise LegacyOSError(f"{context} contains too many TCP options")
    return tuple(options)


def _parse_family(value: str, context: str) -> str:
    if value in {"IPv4", "ipv4"}:
        return "ipv4"
    if value in {"IPv6", "ipv6"}:
        return "ipv6"
    raise LegacyOSError(f"{context} has unsupported address family: {value}")


def _parse_signature(key: str, value: str, line_number: int) -> OSSignature:
    spec = _FIELD_SPECS.get(key)
    if spec is None:
        raise LegacyOSError(f"line {line_number}: unsupported OS field: {key}")
    field_name, operator = spec
    context = f"line {line_number} {key}"
    if operator == "eq":
        parsed_value: int | bool | str | tuple[int, int] | tuple[str, ...] = _parse_unsigned(
            value, context
        )
    elif operator == "range":
        parsed_value = _parse_range(value, context)
    elif operator == "bool":
        parsed_value = _parse_boolean(value, context)
    elif operator == "tcp_options":
        parsed_value = _parse_options(value, context)
    else:
        parsed_value = value
    return OSSignature(field=field_name, operator=operator, value=parsed_value)


def _canonical_record(
    draft: _FingerprintDraft,
    source: SourcePolicy,
    sources: Mapping[str, SourcePolicy],
) -> CanonicalRecord:
    if not draft.class_seen or draft.vendor is None or draft.os_family is None:
        raise LegacyOSError(f"fingerprint {draft.name}: Class is required")
    if not draft.signatures:
        raise LegacyOSError(f"fingerprint {draft.name}: at least one signature is required")
    if draft.expected_family == "ipv6" and not draft.family_seen:
        raise LegacyOSError(
            f"fingerprint {draft.name}: IPv6 runtime corpus requires ADDRESS_FAMILY=IPv6"
        )
    family = draft.address_family or draft.expected_family
    if family != draft.expected_family:
        raise LegacyOSError(
            f"fingerprint {draft.name}: address family {family} does not match {draft.expected_family}"
        )
    runtime_id = draft.runtime_id or draft.name
    specificity = draft.specificity or len(draft.signatures)
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "kind": "os_fingerprint",
        "body": {
            "runtime_id": runtime_id,
            "name": draft.name,
            "vendor": draft.vendor,
            "os_family": draft.os_family,
            "os_generation": draft.os_generation,
            "device_type": draft.device_type,
            "address_family": family,
            "specificity": specificity,
            "signatures": [
                {
                    "field": signature.field,
                    "operator": signature.operator,
                    "value": (
                        list(signature.value)
                        if isinstance(signature.value, tuple)
                        else signature.value
                    ),
                }
                for signature in draft.signatures
            ],
        },
        "provenance": [
            {
                "source_id": source.id,
                "source_record_id": f"os:{family}:{runtime_id}",
                "source_revision": source.pinned_revision,
                "source_url": source.source_url,
                "source_license": source.license_spdx_or_policy,
                "snapshot_hash": source.expected_hash,
                "record_hash": _record_hash(draft.source_lines),
            }
        ],
        "first_imported_revision": source.pinned_revision,
        "last_verified_revision": source.pinned_revision,
        "status": "imported",
        "notes": "Deterministically migrated from the Skan legacy OS runtime corpus.",
    }
    try:
        value["id"] = stable_record_id(value)
        return parse_record(value, sources)
    except CanonicalRecordError as exc:
        raise LegacyOSError(str(exc)) from exc


def parse_legacy_os(
    text: str,
    sources: Mapping[str, SourcePolicy],
    *,
    expected_family: str,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    """Parse one current OS runtime DB into canonical schema-v2 records."""

    if expected_family not in {"ipv4", "ipv6"}:
        raise LegacyOSError("expected_family must be ipv4 or ipv6")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LegacyOSError("legacy OS corpus must be valid UTF-8 text") from exc
    if len(encoded) > _MAXIMUM_DATABASE_BYTES:
        raise LegacyOSError(f"legacy OS corpus exceeds {_MAXIMUM_DATABASE_BYTES} bytes")

    source = _source_policy(sources, source_id)
    records: list[CanonicalRecord] = []
    names: set[str] = set()
    runtime_ids: set[str] = set()
    current: _FingerprintDraft | None = None

    def finalize() -> None:
        nonlocal current
        if current is None:
            return
        if len(records) >= _MAXIMUM_FINGERPRINTS:
            raise LegacyOSError(f"fingerprint count exceeds {_MAXIMUM_FINGERPRINTS}")
        record = _canonical_record(current, source, sources)
        body = record.body
        assert isinstance(body, OSFingerprintSemantics)
        if body.name in names:
            raise LegacyOSError(f"duplicate fingerprint name: {body.name}")
        if body.runtime_id in runtime_ids:
            raise LegacyOSError(f"duplicate fingerprint ID: {body.runtime_id}")
        names.add(body.name)
        runtime_ids.add(body.runtime_id)
        records.append(record)
        current = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line.encode("utf-8")) > _MAXIMUM_LINE_BYTES:
            raise LegacyOSError(f"line {line_number} exceeds {_MAXIMUM_LINE_BYTES} bytes")
        line = _semantic_line(raw_line)
        if not line:
            continue
        if line.startswith("Fingerprint "):
            finalize()
            name = line[12:].strip(" \t\r")
            if not name:
                raise LegacyOSError(f"line {line_number}: fingerprint name is required")
            current = _FingerprintDraft(
                name=name,
                expected_family=expected_family,
                source_lines=[line],
            )
            continue
        if current is None:
            raise LegacyOSError(f"line {line_number}: field appears before Fingerprint")
        current.source_lines.append(line)

        if line.startswith("Class "):
            if current.class_seen:
                raise LegacyOSError(f"line {line_number}: duplicate Class")
            values = [item.strip(" \t\r") for item in line[6:].split("|")]
            if len(values) not in {2, 3, 4} or any(not item for item in values):
                raise LegacyOSError(f"line {line_number}: Class requires 2..4 non-empty components")
            current.vendor = values[0]
            current.os_family = values[1]
            current.os_generation = values[2] if len(values) >= 3 else ""
            current.device_type = values[3] if len(values) == 4 else ""
            current.class_seen = True
            continue

        if "=" not in line:
            raise LegacyOSError(f"line {line_number}: expected KEY=VALUE")
        key, value = (part.strip(" \t\r") for part in line.split("=", 1))
        if not key or not value:
            raise LegacyOSError(f"line {line_number}: KEY and VALUE are required")
        if key == "ID":
            if current.id_seen:
                raise LegacyOSError(f"line {line_number}: duplicate ID")
            current.runtime_id = value
            current.id_seen = True
            continue
        if key == "SPECIFICITY":
            if current.specificity_seen:
                raise LegacyOSError(f"line {line_number}: duplicate SPECIFICITY")
            specificity = _parse_unsigned(value, f"line {line_number} SPECIFICITY", maximum=65535)
            if specificity == 0:
                raise LegacyOSError(f"line {line_number}: SPECIFICITY must be 1..65535")
            current.specificity = specificity
            current.specificity_seen = True
            continue
        if key == "ADDRESS_FAMILY":
            if current.family_seen:
                raise LegacyOSError(f"line {line_number}: duplicate ADDRESS_FAMILY")
            family = _parse_family(value, f"line {line_number} ADDRESS_FAMILY")
            if family != expected_family:
                raise LegacyOSError(
                    f"line {line_number}: address family {family} does not match {expected_family}"
                )
            current.address_family = family
            current.family_seen = True
            continue

        signature = _parse_signature(key, value, line_number)
        if signature.field in current.signature_fields:
            raise LegacyOSError(
                f"line {line_number}: duplicate signature field: {signature.field}"
            )
        if len(current.signatures) >= _MAXIMUM_SIGNATURES:
            raise LegacyOSError(
                f"fingerprint {current.name}: signature count exceeds {_MAXIMUM_SIGNATURES}"
            )
        current.signature_fields.add(signature.field)
        current.signatures.append(signature)

    finalize()
    if not records:
        raise LegacyOSError("legacy OS corpus contains no fingerprints")
    return tuple(records)


def load_legacy_os(
    path: Path,
    sources: Mapping[str, SourcePolicy],
    *,
    expected_family: str,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise LegacyOSError(f"cannot read legacy OS corpus: {exc}") from exc
    if len(raw_bytes) > _MAXIMUM_DATABASE_BYTES:
        raise LegacyOSError(f"legacy OS corpus exceeds {_MAXIMUM_DATABASE_BYTES} bytes")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyOSError("legacy OS corpus must be valid UTF-8") from exc
    return parse_legacy_os(
        text,
        sources,
        expected_family=expected_family,
        source_id=source_id,
    )


def _validated_os_records(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
    *,
    address_family: str,
) -> tuple[CanonicalRecord, ...]:
    if address_family not in {"ipv4", "ipv6"}:
        raise LegacyOSError("address_family must be ipv4 or ipv6")
    validated: list[CanonicalRecord] = []
    names: set[str] = set()
    runtime_ids: set[str] = set()
    for record in records:
        if not isinstance(record, CanonicalRecord):
            raise LegacyOSError("OS compiler input must contain CanonicalRecord values")
        try:
            checked = parse_record(record_to_mapping(record), sources)
        except CanonicalRecordError as exc:
            raise LegacyOSError(str(exc)) from exc
        if checked.kind != "os_fingerprint" or not isinstance(
            checked.body, OSFingerprintSemantics
        ):
            raise LegacyOSError("OS compiler accepts only os_fingerprint records")
        if checked.body.address_family != address_family:
            raise LegacyOSError(
                f"OS compiler expected {address_family}, got {checked.body.address_family}"
            )
        if checked.body.name in names:
            raise LegacyOSError(f"duplicate fingerprint name: {checked.body.name}")
        if checked.body.runtime_id in runtime_ids:
            raise LegacyOSError(f"duplicate fingerprint ID: {checked.body.runtime_id}")
        names.add(checked.body.name)
        runtime_ids.add(checked.body.runtime_id)
        validated.append(checked)
    if not validated:
        raise LegacyOSError("OS compiler requires at least one canonical record")
    if len(validated) > _MAXIMUM_FINGERPRINTS:
        raise LegacyOSError(f"fingerprint count exceeds {_MAXIMUM_FINGERPRINTS}")
    return tuple(validated)


def _compile_signature(signature: OSSignature) -> str:
    field_name = _CANONICAL_FIELD_NAMES.get(signature.field)
    if field_name is None:
        raise LegacyOSError(f"cannot compile unsupported signature field: {signature.field}")
    if signature.operator == "range":
        range_name = _RANGE_FIELD_NAMES.get(signature.field)
        if range_name is None or not isinstance(signature.value, tuple) or len(signature.value) != 2:
            raise LegacyOSError(f"cannot compile range signature: {signature.field}")
        return f"{range_name}={signature.value[0]}-{signature.value[1]}"
    if signature.operator == "bool":
        if type(signature.value) is not bool:
            raise LegacyOSError(f"cannot compile boolean signature: {signature.field}")
        return f"{field_name}={'Y' if signature.value else 'N'}"
    if signature.operator == "tcp_options":
        if not isinstance(signature.value, tuple):
            raise LegacyOSError("cannot compile TCP_OPTIONS signature")
        return f"{field_name}={','.join(signature.value)}"
    if signature.operator == "text":
        if not isinstance(signature.value, str):
            raise LegacyOSError(f"cannot compile text signature: {signature.field}")
        return f"{field_name}={signature.value}"
    if signature.operator == "eq" and type(signature.value) is int:
        return f"{field_name}={signature.value}"
    raise LegacyOSError(
        f"cannot compile signature {signature.field}/{signature.operator} losslessly"
    )


def compile_legacy_os(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
    *,
    address_family: str,
) -> str:
    """Compile canonical OS records into the current C++ runtime DB grammar."""

    validated = _validated_os_records(
        records, sources, address_family=address_family
    )
    ordered = sorted(
        validated,
        key=lambda record: (
            record.body.name,  # type: ignore[union-attr]
            record.body.runtime_id,  # type: ignore[union-attr]
            record.id,
        ),
    )
    family_label = "IPv4" if address_family == "ipv4" else "IPv6"
    lines = [
        f"# Generated from Skan Intelligence Database v2 canonical {family_label} OS records.",
        "# Fingerprint declaration order is non-semantic; evidence fields are canonicalized by OSMatcher.",
        "",
    ]
    for record_index, record in enumerate(ordered):
        body = record.body
        assert isinstance(body, OSFingerprintSemantics)
        lines.append(f"Fingerprint {body.name}")
        lines.append(f"ID={body.runtime_id}")
        lines.append(f"SPECIFICITY={body.specificity}")
        lines.append(f"ADDRESS_FAMILY={family_label}")
        class_values = [body.vendor, body.os_family]
        if body.os_generation:
            class_values.append(body.os_generation)
        if body.device_type:
            if not body.os_generation:
                raise LegacyOSError("device_type requires os_generation")
            class_values.append(body.device_type)
        lines.append("Class " + " | ".join(class_values))
        for signature in body.signatures:
            lines.append(_compile_signature(signature))
        if record_index + 1 < len(ordered):
            lines.append("")
    return "\n".join(lines) + "\n"


def semantic_os_ids(records: Iterable[CanonicalRecord]) -> tuple[str, ...]:
    collected = tuple(records)
    for record in collected:
        if record.kind != "os_fingerprint" or not isinstance(
            record.body, OSFingerprintSemantics
        ):
            raise LegacyOSError("semantic OS comparison accepts only os_fingerprint records")
    ordered = sorted(
        collected,
        key=lambda record: (
            record.body.address_family,  # type: ignore[union-attr]
            record.body.runtime_id,  # type: ignore[union-attr]
            record.id,
        ),
    )
    return tuple(record.id for record in ordered)


def verify_os_round_trip(
    expected: Iterable[CanonicalRecord], actual: Iterable[CanonicalRecord]
) -> None:
    if semantic_os_ids(expected) != semantic_os_ids(actual):
        raise LegacyOSError("OS semantic round-trip mismatch")
