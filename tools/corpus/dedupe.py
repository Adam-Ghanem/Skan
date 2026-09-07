from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from tools.corpus.model import CanonicalRecord, Provenance


_STATUS_RANK = {
    "suppressed": 0,
    "deprecated": 1,
    "experimental": 2,
    "imported": 3,
    "verified": 4,
}


@dataclass(frozen=True)
class Conflict:
    left_id: str
    right_id: str
    differing_fields: tuple[str, ...]


def _provenance_key(value: Provenance) -> tuple[str, str, str, str, str, str]:
    return (
        value.source_id,
        value.source_record_id,
        value.source_revision,
        value.source_hash,
        value.source_url,
        value.source_license,
    )


def _merge_provenance(records: Iterable[CanonicalRecord]) -> tuple[Provenance, ...]:
    unique: dict[tuple[str, str, str, str, str, str], Provenance] = {}
    for record in records:
        for item in record.provenance:
            unique[_provenance_key(item)] = item
    return tuple(unique[key] for key in sorted(unique))


def _merge_exact(records: list[CanonicalRecord]) -> CanonicalRecord:
    if not records:
        raise ValueError("cannot merge an empty exact-record group")

    ordered = sorted(
        records,
        key=lambda record: (
            -_STATUS_RANK.get(record.status, -1),
            -(record.confidence if record.confidence is not None else -1.0),
            record.first_imported_revision,
            record.last_verified_revision,
            record.notes,
        ),
    )
    base = ordered[0]

    status = max(records, key=lambda record: _STATUS_RANK.get(record.status, -1)).status
    confidences = [record.confidence for record in records if record.confidence is not None]
    confidence = max(confidences) if confidences else None
    confidence_bases = sorted(
        {
            record.confidence_basis.strip()
            for record in records
            if record.confidence_basis.strip()
        }
    )
    notes = sorted({record.notes.strip() for record in records if record.notes.strip()})
    first_revisions = sorted(
        {record.first_imported_revision for record in records if record.first_imported_revision}
    )
    last_revisions = sorted(
        {record.last_verified_revision for record in records if record.last_verified_revision}
    )

    return replace(
        base,
        status=status,
        confidence=confidence,
        confidence_basis="; ".join(confidence_bases),
        provenance=_merge_provenance(records),
        first_imported_revision=first_revisions[0] if first_revisions else "",
        last_verified_revision=last_revisions[-1] if last_revisions else "",
        notes="; ".join(notes),
    )


def _conflict_key(record: CanonicalRecord) -> tuple[object, ...] | None:
    if record.kind not in {"service_matcher", "os_fingerprint"}:
        return None
    return (
        record.kind,
        record.transport,
        record.address_family,
        record.probe_id,
        record.matcher_type,
        record.matcher_expression,
        tuple(sorted(set(record.ports))),
    )


def _identity(record: CanonicalRecord) -> dict[str, str | None]:
    return {
        "service": record.service,
        "vendor": record.vendor,
        "product": record.product,
        "version": record.version,
        "os_family": record.os_family,
        "device_type": record.device_type,
    }


def _differing_identity_fields(left: CanonicalRecord, right: CanonicalRecord) -> tuple[str, ...]:
    left_identity = _identity(left)
    right_identity = _identity(right)
    return tuple(
        field
        for field in sorted(left_identity)
        if left_identity[field] != right_identity[field]
    )


def merge_records(
    records: list[CanonicalRecord],
) -> tuple[list[CanonicalRecord], list[Conflict]]:
    by_id: dict[str, list[CanonicalRecord]] = {}
    for record in records:
        by_id.setdefault(record.id, []).append(record)

    merged = [_merge_exact(group) for _, group in sorted(by_id.items())]
    merged.sort(key=lambda record: record.id)

    by_conflict_key: dict[tuple[object, ...], list[CanonicalRecord]] = {}
    for record in merged:
        key = _conflict_key(record)
        if key is not None:
            by_conflict_key.setdefault(key, []).append(record)

    conflicts: list[Conflict] = []
    seen_pairs: set[tuple[str, str]] = set()
    for group in by_conflict_key.values():
        ordered = sorted(group, key=lambda record: record.id)
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                differing = _differing_identity_fields(left, right)
                if not differing:
                    continue
                pair = (left.id, right.id)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                conflicts.append(
                    Conflict(
                        left_id=pair[0],
                        right_id=pair[1],
                        differing_fields=differing,
                    )
                )

    conflicts.sort(key=lambda conflict: (conflict.left_id, conflict.right_id))
    return merged, conflicts
