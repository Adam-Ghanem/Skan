from __future__ import annotations

from pathlib import Path
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
from tools.corpus.runtime import ImportContext, RuntimeCorpusError, parse_udp_runtime
from tools.corpus.sources import SourcePolicy


_MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
_LEGACY_UDP_SOURCE_PATH = "data/udp-probes.db"


class LegacyUDPError(ValueError):
    """The legacy UDP corpus cannot be migrated or compiled losslessly."""


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
    record_hash: str,
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
                "record_hash": record_hash,
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


def _legacy_runtime_error(error: RuntimeCorpusError) -> LegacyUDPError:
    """Translate unified-parser errors at the legacy public API boundary."""

    message = str(error)
    message = message.replace("malformed UDP probe", "expected `probe NAME PORT HINT MAX_RESPONSE PAYLOAD_HEX`")
    message = message.replace("duplicate UDP probe name", "duplicate probe name")
    message = message.replace("duplicate UDP port", "duplicate destination port")
    if message == "UDP runtime contains no probes":
        message = "legacy UDP corpus contains no probe definitions"
    elif message == "missing DEFAULT UDP probe":
        message = "legacy UDP corpus requires exactly one DEFAULT probe"
    elif message == "invalid UDP max_response_bytes":
        message = "max response must be in range 1..1048576"
    return LegacyUDPError(message)


def _legacy_records_from_runtime(
    runtime_records: tuple[CanonicalRecord, ...],
    source: SourcePolicy,
    sources: Mapping[str, SourcePolicy],
) -> tuple[CanonicalRecord, ...]:
    """Rebind unified grammar output to the stable legacy metadata contract.

    ``parse_udp_runtime`` is the only UDP grammar implementation.  This adapter
    deliberately retains legacy source IDs, imported status, and line hashes so
    existing canonical UDP artifacts keep their semantic IDs.
    """

    records: list[CanonicalRecord] = []
    for runtime_record in runtime_records:
        body = runtime_record.body
        if not isinstance(body, UDPProbeSemantics):
            raise LegacyUDPError("UDP runtime parser returned a non-UDP record")
        records.append(
            _canonical_udp_record(
                name=body.name,
                destination_port=body.destination_port,
                protocol_hint=body.protocol_hint,
                max_response_bytes=body.max_response_bytes,
                payload_hex=body.payload_hex,
                declaration_order=body.declaration_order,
                record_hash=runtime_record.provenance[0].record_hash,
                source=source,
                sources=sources,
            )
        )
    return tuple(records)


def parse_legacy_udp(
    text: str,
    sources: Mapping[str, SourcePolicy],
    *,
    source_id: str = "skan-first-party",
) -> tuple[CanonicalRecord, ...]:
    """Parse UDP runtime text through the unified bounded runtime grammar."""

    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LegacyUDPError("legacy UDP corpus must be valid UTF-8 text") from exc
    if len(encoded) > _MAXIMUM_FILE_BYTES:
        raise LegacyUDPError(f"legacy UDP corpus exceeds {_MAXIMUM_FILE_BYTES} bytes")

    source = _source_policy(sources, source_id)
    try:
        runtime_records = parse_udp_runtime(
            encoded, ImportContext(source, _LEGACY_UDP_SOURCE_PATH)
        )
    except RuntimeCorpusError as exc:
        raise _legacy_runtime_error(exc) from exc
    return _legacy_records_from_runtime(runtime_records, source, sources)


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
