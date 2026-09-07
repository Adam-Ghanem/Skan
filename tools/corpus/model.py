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
_ALLOWED_MATCH_STRENGTHS = {"hard", "soft"}
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


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
    probe_payload_hex: str | None = None
    probe_priority: int | None = None
    probe_timeout_ms: int | None = None
    fallback_probe_ids: tuple[str, ...] = ()
    match_strength: str | None = None
    extra_template: str | None = None
    hostname_template: str | None = None
    tunnel_template: str | None = None
    protocol_hint: str | None = None
    max_response_bytes: int | None = None
    fingerprint_name: str | None = None
    fingerprint_native_id: str | None = None
    specificity: int | None = None
    os_features: tuple[tuple[str, str], ...] = ()


def _normalized_strings(values: tuple[str, ...]) -> list[str]:
    return sorted(set(values))


def _normalized_os_features(values: tuple[tuple[str, str], ...]) -> list[list[str]]:
    return [[key, value] for key, value in sorted(values, key=lambda item: item[0])]


def _normalized_payload_hex(value: str | None) -> str | None:
    return None if value is None else value.lower()


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
        "probe_payload_hex": _normalized_payload_hex(record.probe_payload_hex),
        "probe_priority": record.probe_priority,
        "probe_timeout_ms": record.probe_timeout_ms,
        "fallback_probe_ids": list(record.fallback_probe_ids),
        "match_strength": record.match_strength,
        "extra_template": record.extra_template,
        "hostname_template": record.hostname_template,
        "tunnel_template": record.tunnel_template,
        "protocol_hint": record.protocol_hint,
        "max_response_bytes": record.max_response_bytes,
        "fingerprint_name": record.fingerprint_name,
        "fingerprint_native_id": record.fingerprint_native_id,
        "specificity": record.specificity,
        "os_features": _normalized_os_features(record.os_features),
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


def _valid_payload_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) % 2 == 0
        and all(character in _HEX_CHARS for character in value)
    )


def _validate_os_features(values: object) -> list[str]:
    if not isinstance(values, tuple):
        return ["os_features must be a tuple of (key, value) pairs"]

    keys: list[str] = []
    for item in values:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or not item[0].strip()
        ):
            return ["os_features must contain non-empty string keys and string values"]
        keys.append(item[0])

    if len(keys) != len(set(keys)):
        return ["os_features must not contain duplicate keys"]
    return []


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

    if record.probe_payload_hex is not None and not _valid_payload_hex(record.probe_payload_hex):
        errors.append("probe_payload_hex must be even-length hexadecimal text or null")
    if record.probe_priority is not None and (
        type(record.probe_priority) is not int or record.probe_priority < 0
    ):
        errors.append("probe_priority must be a non-negative integer or null")
    if record.probe_timeout_ms is not None and (
        type(record.probe_timeout_ms) is not int or record.probe_timeout_ms <= 0
    ):
        errors.append("probe_timeout_ms must be a positive integer or null")

    if not isinstance(record.fallback_probe_ids, tuple):
        errors.append("fallback_probe_ids must be a tuple of strings")
    else:
        invalid_fallbacks = [
            value
            for value in record.fallback_probe_ids
            if not isinstance(value, str) or not value.strip()
        ]
        if invalid_fallbacks or len(record.fallback_probe_ids) != len(set(record.fallback_probe_ids)):
            errors.append("fallback_probe_ids must contain unique non-empty strings")

    if record.match_strength is not None and record.match_strength not in _ALLOWED_MATCH_STRENGTHS:
        errors.append("match_strength must be hard, soft, or null")
    if record.protocol_hint is not None and (
        not isinstance(record.protocol_hint, str) or not record.protocol_hint.strip()
    ):
        errors.append("protocol_hint must be a non-empty string or null")
    if record.max_response_bytes is not None and (
        type(record.max_response_bytes) is not int or record.max_response_bytes <= 0
    ):
        errors.append("max_response_bytes must be a positive integer or null")
    if record.specificity is not None and (
        type(record.specificity) is not int or record.specificity < 0
    ):
        errors.append("specificity must be a non-negative integer or null")

    errors.extend(_validate_os_features(record.os_features))

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
        if not record.probe_id:
            errors.append("service_matcher requires probe_id")
        if not record.matcher_type:
            errors.append("service_matcher requires matcher_type")
        if not record.matcher_expression:
            errors.append("service_matcher requires matcher_expression")
        if not record.service:
            errors.append("service_matcher requires service")
        if record.match_strength not in _ALLOWED_MATCH_STRENGTHS:
            errors.append("service_matcher requires match_strength hard or soft")
    elif record.kind == "active_probe":
        if not record.probe_id:
            errors.append("active_probe requires probe_id")
        if record.probe_payload_hex is None:
            errors.append("active_probe requires probe_payload_hex")
        if record.probe_timeout_ms is None:
            errors.append("active_probe requires probe_timeout_ms")
    elif record.kind == "udp_probe":
        if not record.probe_id:
            errors.append("udp_probe requires probe_id")
        if len(record.ports) != 1:
            errors.append("udp_probe requires exactly one port")
        if not record.protocol_hint:
            errors.append("udp_probe requires protocol_hint")
        if record.max_response_bytes is None:
            errors.append("udp_probe requires max_response_bytes")
        if record.probe_payload_hex is None:
            errors.append("udp_probe requires probe_payload_hex")
    elif record.kind == "os_fingerprint":
        if not record.fingerprint_name:
            errors.append("os_fingerprint requires fingerprint_name")
        if not record.os_family:
            errors.append("os_fingerprint requires os_family")
        if not record.os_features:
            errors.append("os_fingerprint requires os_features")

    expected_id = stable_record_id(record)
    if record.id and record.id != expected_id:
        errors.append(f"id does not match semantic fingerprint: expected {expected_id}")

    return errors
