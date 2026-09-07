from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id, validate_record
from tools.corpus.sources import SourcePolicy


def _sorted_unique_strings(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def _provenance_key(value: Provenance) -> tuple[str, str, str, str]:
    return (
        value.source_id,
        value.source_record_id,
        value.source_revision,
        value.source_hash,
    )


def record_to_dict(record: CanonicalRecord) -> dict[str, object]:
    expected_id = stable_record_id(record)
    if record.id and record.id != expected_id:
        raise ValueError(f"id does not match semantic fingerprint: expected {expected_id}")

    return {
        "id": expected_id,
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
        "cpe": _sorted_unique_strings(record.cpe),
        "ports": sorted(set(record.ports)),
        "rarity": record.rarity,
        "confidence": record.confidence,
        "confidence_basis": record.confidence_basis,
        "evidence_requirements": _sorted_unique_strings(record.evidence_requirements),
        "negative_constraints": _sorted_unique_strings(record.negative_constraints),
        "provenance": [
            {
                "source_id": item.source_id,
                "source_record_id": item.source_record_id,
                "source_revision": item.source_revision,
                "source_url": item.source_url,
                "source_license": item.source_license,
                "source_hash": item.source_hash,
            }
            for item in sorted(record.provenance, key=_provenance_key)
        ],
        "first_imported_revision": record.first_imported_revision,
        "last_verified_revision": record.last_verified_revision,
        "status": record.status,
        "notes": record.notes,
    }


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, name)


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(value)


def _int_tuple(value: Any, name: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(type(item) is not int for item in value):
        raise ValueError(f"{name} must be an array of integers")
    return tuple(value)


def record_from_dict(raw_value: Mapping[str, Any]) -> CanonicalRecord:
    raw = dict(raw_value)
    provenance_raw = raw.get("provenance")
    if not isinstance(provenance_raw, list):
        raise ValueError("provenance must be an array")

    provenance: list[Provenance] = []
    for index, item_value in enumerate(provenance_raw):
        item = _require_object(item_value, f"provenance[{index}]")
        provenance.append(
            Provenance(
                source_id=_require_string(item.get("source_id"), "source_id"),
                source_record_id=_require_string(item.get("source_record_id"), "source_record_id"),
                source_revision=_require_string(item.get("source_revision"), "source_revision"),
                source_url=_require_string(item.get("source_url"), "source_url"),
                source_license=_require_string(item.get("source_license"), "source_license"),
                source_hash=_require_string(item.get("source_hash"), "source_hash"),
            )
        )

    rarity = raw.get("rarity")
    if rarity is not None and type(rarity) is not int:
        raise ValueError("rarity must be an integer or null")
    confidence = raw.get("confidence")
    if confidence is not None and type(confidence) not in (int, float):
        raise ValueError("confidence must be numeric or null")

    return CanonicalRecord(
        id=_require_string(raw.get("id"), "id"),
        kind=_require_string(raw.get("kind"), "kind"),
        transport=_require_string(raw.get("transport"), "transport"),
        address_family=_require_string(raw.get("address_family"), "address_family"),
        probe_id=_optional_string(raw.get("probe_id"), "probe_id"),
        probe_payload_ref=_optional_string(raw.get("probe_payload_ref"), "probe_payload_ref"),
        matcher_type=_optional_string(raw.get("matcher_type"), "matcher_type"),
        matcher_expression=_optional_string(raw.get("matcher_expression"), "matcher_expression"),
        service=_optional_string(raw.get("service"), "service"),
        vendor=_optional_string(raw.get("vendor"), "vendor"),
        product=_optional_string(raw.get("product"), "product"),
        version=_optional_string(raw.get("version"), "version"),
        version_info=_optional_string(raw.get("version_info"), "version_info"),
        os_family=_optional_string(raw.get("os_family"), "os_family"),
        os_generation=_optional_string(raw.get("os_generation"), "os_generation"),
        device_type=_optional_string(raw.get("device_type"), "device_type"),
        cpe=_string_tuple(raw.get("cpe"), "cpe"),
        ports=_int_tuple(raw.get("ports"), "ports"),
        rarity=rarity,
        confidence=None if confidence is None else float(confidence),
        confidence_basis=_require_string(raw.get("confidence_basis"), "confidence_basis"),
        evidence_requirements=_string_tuple(raw.get("evidence_requirements"), "evidence_requirements"),
        negative_constraints=_string_tuple(raw.get("negative_constraints"), "negative_constraints"),
        provenance=tuple(provenance),
        first_imported_revision=_require_string(raw.get("first_imported_revision"), "first_imported_revision"),
        last_verified_revision=_require_string(raw.get("last_verified_revision"), "last_verified_revision"),
        status=_require_string(raw.get("status"), "status"),
        notes=_require_string(raw.get("notes"), "notes"),
    )


def load_jsonl(path: Path, sources: Mapping[str, SourcePolicy]) -> list[CanonicalRecord]:
    if not path.exists():
        raise ValueError(f"canonical file does not exist: {path}")
    if path.stat().st_size == 0:
        return []

    records: list[CanonicalRecord] = []
    seen_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise ValueError(f"blank JSONL line at {path}:{line_number}")
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc.msg}") from exc
            raw = _require_object(parsed, f"record at line {line_number}")
            record = record_from_dict(raw)
            errors = validate_record(record, sources)
            if errors:
                raise ValueError(f"invalid canonical record at {path}:{line_number}: {'; '.join(errors)}")
            if record.id in seen_ids:
                raise ValueError(f"duplicate canonical id: {record.id}")
            seen_ids.add(record.id)
            records.append(record)
    return sorted(records, key=lambda record: record.id)


def write_jsonl(path: Path, records: Iterable[CanonicalRecord]) -> None:
    serialized = [record_to_dict(record) for record in records]
    serialized.sort(key=lambda item: str(item["id"]))
    ids = [str(item["id"]) for item in serialized]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate canonical id in write set")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for item in serialized:
            handle.write(
                json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            handle.write("\n")
