from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from tools.corpus.sources import SourcePolicy


_ALLOWED_KINDS = {
    "service_matcher",
    "active_probe",
    "os_fingerprint",
    "udp_probe",
    "product_vocab",
    "registry",
}
_ALLOWED_TRANSPORTS = {"tcp", "udp", "any", "none"}
_ALLOWED_ADDRESS_FAMILIES = {"ipv4", "ipv6", "any", "none"}
_ALLOWED_STATUSES = {"verified", "imported", "experimental", "suppressed", "deprecated"}


@dataclass(frozen=True)
class Provenance:
    source_id: str
    source_record_id: str
    source_revision: str
    source_url: str
    source_license: str
    source_hash: str


@dataclass(frozen=True)
class CanonicalRecord:
    id: str
    kind: str
    transport: str
    address_family: str
    probe_id: str | None
    probe_payload_ref: str | None
    matcher_type: str | None
    matcher_expression: str | None
    service: str | None
    vendor: str | None
    product: str | None
    version: str | None
    version_info: str | None
    os_family: str | None
    os_generation: str | None
    device_type: str | None
    cpe: tuple[str, ...]
    ports: tuple[int, ...]
    rarity: int | None
    confidence: float | None
    confidence_basis: str
    evidence_requirements: tuple[str, ...]
    negative_constraints: tuple[str, ...]
    provenance: tuple[Provenance, ...]
    first_imported_revision: str
    last_verified_revision: str
    status: str
    notes: str


def _normalized_strings(values: tuple[str, ...]) -> list[str]:
    return sorted(set(values))


def _semantic_payload(record: CanonicalRecord) -> dict[str, object]:
    return {
        "kind": record.kind,
        "transport": record.transport,
        "address_family": record.address_family,
        "probe_id": record.probe_id,
        "probe_payload_ref": record.probe_payload_ref,
        "matcher_type": record.matcher_type,
        "matcher_expression": record.matcher_expression,
        "service": record.service,
        "vendor": record.vendor,
        "product": record.product,
        "version": record.version,
        "version_info": record.version_info,
        "os_family": record.os_family,
        "os_generation": record.os_generation,
        "device_type": record.device_type,
        "cpe": _normalized_strings(record.cpe),
        "ports": sorted(set(record.ports)),
        "rarity": record.rarity,
        "evidence_requirements": _normalized_strings(record.evidence_requirements),
        "negative_constraints": _normalized_strings(record.negative_constraints),
    }


def stable_record_id(record: CanonicalRecord) -> str:
    encoded = json.dumps(
        _semantic_payload(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "skan-fp-v2-" + hashlib.sha256(encoded).hexdigest()[:24]


def _valid_sha256(value: str) -> bool:
    prefix = "sha256:"
    if not value.startswith(prefix):
        return False
    digest = value[len(prefix) :]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def validate_record(
    record: CanonicalRecord,
    sources: Mapping[str, SourcePolicy],
) -> list[str]:
    errors: list[str] = []

    if record.kind not in _ALLOWED_KINDS:
        errors.append(f"unsupported kind: {record.kind}")
    if record.transport not in _ALLOWED_TRANSPORTS:
        errors.append(f"unsupported transport: {record.transport}")
    if record.address_family not in _ALLOWED_ADDRESS_FAMILIES:
        errors.append(f"unsupported address_family: {record.address_family}")
    if record.status not in _ALLOWED_STATUSES:
        errors.append(f"unsupported status: {record.status}")

    if record.confidence is not None:
        if type(record.confidence) not in (int, float) or not 0.0 <= float(record.confidence) <= 1.0:
            errors.append("confidence must be within [0.0, 1.0]")
    if record.rarity is not None and (type(record.rarity) is not int or record.rarity < 0):
        errors.append("rarity must be a non-negative integer or null")

    invalid_ports = [port for port in record.ports if type(port) is not int or not 0 <= port <= 65535]
    if invalid_ports:
        errors.append("ports must contain integers in range 0..65535")

    if not record.provenance:
        errors.append("provenance must contain at least one source contribution")
    for provenance in record.provenance:
        source = sources.get(provenance.source_id)
        if source is None:
            errors.append(f"unknown source_id: {provenance.source_id}")
            continue
        if not provenance.source_record_id.strip():
            errors.append(f"source {provenance.source_id}: source_record_id is required")
        if not provenance.source_revision.strip():
            errors.append(f"source {provenance.source_id}: source_revision is required")
        if not provenance.source_url.strip():
            errors.append(f"source {provenance.source_id}: source_url is required")
        if provenance.source_license != source.license_spdx_or_policy:
            errors.append(f"source {provenance.source_id}: source_license does not match manifest")
        if not _valid_sha256(provenance.source_hash):
            errors.append(f"source {provenance.source_id}: source_hash must be sha256:<64 lowercase hex chars>")

    if record.kind == "service_matcher":
        if not record.matcher_type:
            errors.append("service_matcher requires matcher_type")
        if not record.matcher_expression:
            errors.append("service_matcher requires matcher_expression")
        if not record.service:
            errors.append("service_matcher requires service")
    elif record.kind == "active_probe":
        if not record.probe_id:
            errors.append("active_probe requires probe_id")
    elif record.kind == "os_fingerprint":
        if not record.os_family:
            errors.append("os_fingerprint requires os_family")

    expected_id = stable_record_id(record)
    if record.id and record.id != expected_id:
        errors.append(f"id does not match semantic fingerprint: expected {expected_id}")

    return errors
