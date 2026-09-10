from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Iterable, Mapping

from tools.corpus.model import (
    CanonicalRecord,
    CanonicalRecordError,
    SCHEMA_VERSION,
    UDPProbeSemantics,
    parse_record,
    record_to_mapping,
    stable_record_id,
)
from tools.corpus.sources import SourcePolicy


_MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
_MAXIMUM_LINE_BYTES = 64 * 1024
_MAXIMUM_RECORDS = 10_000
_MAXIMUM_PAYLOAD_BYTES = 512
_MAXIMUM_RESPONSE_BYTES = 1 << 20
_DECIMAL = re.compile(r"^[0-9]+$")
_HEXADECIMAL = re.compile(r"^[0-9A-Fa-f]+$")


class LegacyUDPError(ValueError):
    """The legacy UDP corpus cannot be migrated or compiled losslessly."""


def _parse_decimal(value: str, field: str, maximum: int, *, allow_zero: bool) -> int:
    if _DECIMAL.fullmatch(value) is None:
        raise LegacyUDPError(f"{field} must be an unsigned decimal integer")
    parsed = int(value, 10)
    minimum = 0 if allow_zero else 1
    if not minimum <= parsed <= maximum:
        raise LegacyUDPError(f"{field} must be in range {minimum}..{maximum}")
    return parsed


def _record_hash(source_line: str) -> str:
    return "sha256:" + hashlib.sha256(source_line.encode("utf-8")).hexdigest()


def _source_policy(
    sources: Mapping[str, SourcePolicy], source_id: str
) -> SourcePolicy:
    policy = sources.get(source_id)
    if policy is None:
        raise LegacyUDPError(f"unknown source_id: {source_id}")
    if "udp_probe" not in policy.approved_data_classes or "udp_probe" in policy.blocked_data_classes:
        raise LegacyUDPError(f"source is not authorized for udp_probe: {source_id}")
    return policy


def _canonical_udp_record(
    *,
    name: str,
    destination_port: int,
    protocol_hint: str,
    max_response_bytes: int,
    payload_hex: str,
    declaration_order: int,
    source_line: str,
    source: SourcePolicy,
    sources: Mapping[str, SourcePolicy],
) -> CanonicalRecord:
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "id": "",
        "kind": "udp_probe",
        "body": {
            "name": name,
            "destination_port": destination_port,
            "protocol_hint": protocol_hint,
            "max_response_bytes": max_response_bytes,
            "payload_hex": payload_hex,
            "declaration_order": declaration_order,
        },
        "provenance": [
            {
                "source_id": source.id,
                "source_record_id": f"udp:{name}",
                "source_revision": source.pinned_revision,
                "source_url": source.source_url,
                "source_license": source.license_spdx_or_policy,
                "snapshot_hash": source.expected_hash,
                "record_hash": _record_hash(source_line),
            }
        ],
        "first_imported_revision": source.pinned_revision,
        "last_verified_revision": source.pinned_revision,
        "status": "imported",
        "notes": "Deterministically migrated from the Skan legacy UDP runtime corpus.",
    }
    try:
        value["id"] = stable_record_id(value)
        return parse_record(value, sources)
    except CanonicalRecordError as exc:
        raise LegacyUDPError(str(exc)) from exc


def parse_legacy_udp(
    text: str,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    """Parse the current C++ UDP line format into canonical schema-v2 records.

    The accepted runtime grammar is deliberately narrow and mirrors
    UDPProbeDatabase::parse: `probe NAME PORT HINT MAX_RESPONSE PAYLOAD_HEX`.
    Comments and blank lines are non-semantic. Hexadecimal payloads are
    normalized to lowercase before canonicalization.
    """

    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LegacyUDPError("legacy UDP corpus must be valid UTF-8 text") from exc
    if len(encoded) > _MAXIMUM_FILE_BYTES:
        raise LegacyUDPError(f"legacy UDP corpus exceeds {_MAXIMUM_FILE_BYTES} bytes")

    source = _source_policy(sources, source_id)
    records: list[CanonicalRecord] = []
    names: set[str] = set()
    ports: set[int] = set()
    has_default = False

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line.encode("utf-8")) > _MAXIMUM_LINE_BYTES:
            raise LegacyUDPError(f"line {line_number} exceeds {_MAXIMUM_LINE_BYTES} bytes")
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(records) >= _MAXIMUM_RECORDS:
            raise LegacyUDPError(f"record count exceeds {_MAXIMUM_RECORDS}")

        fields = line.split()
        if len(fields) != 6 or fields[0] != "probe":
            raise LegacyUDPError(
                f"line {line_number}: expected `probe NAME PORT HINT MAX_RESPONSE PAYLOAD_HEX`"
            )
        _, name, port_text, protocol_hint, response_text, payload_text = fields
        if not name or not protocol_hint:
            raise LegacyUDPError(f"line {line_number}: name and protocol hint are required")
        if name in names:
            raise LegacyUDPError(f"line {line_number}: duplicate probe name: {name}")

        destination_port = _parse_decimal(
            port_text, f"line {line_number} destination port", 65535, allow_zero=True
        )
        max_response_bytes = _parse_decimal(
            response_text,
            f"line {line_number} max response",
            _MAXIMUM_RESPONSE_BYTES,
            allow_zero=False,
        )
        if destination_port == 0 and name != "DEFAULT":
            raise LegacyUDPError(f"line {line_number}: port 0 is reserved for DEFAULT")
        if destination_port != 0 and destination_port in ports:
            raise LegacyUDPError(
                f"line {line_number}: duplicate destination port: {destination_port}"
            )
        if destination_port == 0:
            if has_default:
                raise LegacyUDPError(f"line {line_number}: duplicate DEFAULT probe")
            has_default = True
        else:
            ports.add(destination_port)

        if (
            not payload_text
            or len(payload_text) % 2 != 0
            or _HEXADECIMAL.fullmatch(payload_text) is None
        ):
            raise LegacyUDPError(f"line {line_number}: payload must be even-length hexadecimal")
        if len(payload_text) // 2 > _MAXIMUM_PAYLOAD_BYTES:
            raise LegacyUDPError(
                f"line {line_number}: payload exceeds {_MAXIMUM_PAYLOAD_BYTES} bytes"
            )

        records.append(
            _canonical_udp_record(
                name=name,
                destination_port=destination_port,
                protocol_hint=protocol_hint,
                max_response_bytes=max_response_bytes,
                payload_hex=payload_text.lower(),
                declaration_order=len(records),
                source_line=line,
                source=source,
                sources=sources,
            )
        )
        names.add(name)

    if not records:
        raise LegacyUDPError("legacy UDP corpus contains no probe definitions")
    if not has_default:
        raise LegacyUDPError("legacy UDP corpus requires exactly one DEFAULT probe")
    return tuple(records)


def load_legacy_udp(
    path: Path,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise LegacyUDPError(f"cannot read legacy UDP corpus: {exc}") from exc
    if len(raw_bytes) > _MAXIMUM_FILE_BYTES:
        raise LegacyUDPError(f"legacy UDP corpus exceeds {_MAXIMUM_FILE_BYTES} bytes")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyUDPError("legacy UDP corpus must be valid UTF-8") from exc
    return parse_legacy_udp(text, sources, source_id=source_id)


def _validated_udp_records(
    records: Iterable[CanonicalRecord], sources: Mapping[str, SourcePolicy]
) -> tuple[CanonicalRecord, ...]:
    validated: list[CanonicalRecord] = []
    for record in records:
        if not isinstance(record, CanonicalRecord):
            raise LegacyUDPError("compiler input must contain CanonicalRecord values")
        try:
            checked = parse_record(record_to_mapping(record), sources)
        except CanonicalRecordError as exc:
            raise LegacyUDPError(str(exc)) from exc
        if checked.kind != "udp_probe" or not isinstance(checked.body, UDPProbeSemantics):
            raise LegacyUDPError("UDP compiler accepts only udp_probe records")
        validated.append(checked)
    if not validated:
        raise LegacyUDPError("UDP compiler requires at least one canonical record")
    return tuple(validated)


def compile_legacy_udp(
    records: Iterable[CanonicalRecord], sources: Mapping[str, SourcePolicy]
) -> str:
    """Compile canonical UDP records into the current C++ runtime DB grammar."""

    validated = _validated_udp_records(records, sources)
    ordered = sorted(validated, key=lambda record: record.body.declaration_order)  # type: ignore[union-attr]
    orders = tuple(record.body.declaration_order for record in ordered)  # type: ignore[union-attr]
    if orders != tuple(range(len(ordered))):
        raise LegacyUDPError("UDP declaration_order values must be contiguous from zero")

    names: set[str] = set()
    ports: set[int] = set()
    has_default = False
    lines = [
        "# Generated from Skan Intelligence Database v2 canonical UDP records.",
        "# Syntax: probe NAME PORT PROTOCOL_HINT MAX_RESPONSE_BYTES PAYLOAD_HEX",
    ]
    for record in ordered:
        body = record.body
        assert isinstance(body, UDPProbeSemantics)
        if body.name in names:
            raise LegacyUDPError(f"duplicate probe name: {body.name}")
        names.add(body.name)
        if body.destination_port == 0:
            if body.name != "DEFAULT" or has_default:
                raise LegacyUDPError("runtime corpus requires exactly one DEFAULT probe on port 0")
            has_default = True
        else:
            if body.destination_port in ports:
                raise LegacyUDPError(f"duplicate destination port: {body.destination_port}")
            ports.add(body.destination_port)
        lines.append(
            "probe "
            f"{body.name} {body.destination_port} {body.protocol_hint} "
            f"{body.max_response_bytes} {body.payload_hex}"
        )
    if not has_default:
        raise LegacyUDPError("runtime corpus requires exactly one DEFAULT probe")
    return "\n".join(lines) + "\n"


def semantic_udp_ids(records: Iterable[CanonicalRecord]) -> tuple[str, ...]:
    """Return runtime-semantic IDs in declaration order for equivalence checks."""

    collected = tuple(records)
    if any(record.kind != "udp_probe" for record in collected):
        raise LegacyUDPError("semantic UDP comparison accepts only udp_probe records")
    ordered = sorted(collected, key=lambda record: record.body.declaration_order)  # type: ignore[union-attr]
    return tuple(record.id for record in ordered)


def verify_udp_round_trip(
    expected: Iterable[CanonicalRecord], actual: Iterable[CanonicalRecord]
) -> None:
    expected_ids = semantic_udp_ids(expected)
    actual_ids = semantic_udp_ids(actual)
    if expected_ids != actual_ids:
        raise LegacyUDPError("UDP semantic round-trip mismatch")
