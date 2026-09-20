from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id


@dataclass(frozen=True)
class AdapterContext:
    source_id: str
    revision: str
    source_url: str
    source_license: str
    source_hash: str

    def provenance(self, source_record_id: str) -> tuple[Provenance, ...]:
        if not source_record_id.strip():
            raise ValueError("source_record_id is required")
        return (
            Provenance(
                source_id=self.source_id,
                source_record_id=source_record_id,
                source_revision=self.revision,
                source_url=self.source_url,
                source_license=self.source_license,
                source_hash=self.source_hash,
            ),
        )


def make_record(
    context: AdapterContext,
    source_record_id: str,
    kind: str,
    **changes: Any,
) -> CanonicalRecord:
    values: dict[str, Any] = {
        "id": "",
        "kind": kind,
        "transport": "none",
        "address_family": "none",
        "probe_id": None,
        "probe_payload_ref": None,
        "matcher_type": None,
        "matcher_expression": None,
        "service": None,
        "vendor": None,
        "product": None,
        "version": None,
        "version_info": None,
        "os_family": None,
        "os_generation": None,
        "device_type": None,
        "cpe": (),
        "ports": (),
        "rarity": None,
        "confidence": None,
        "confidence_basis": "metadata",
        "evidence_requirements": (),
        "negative_constraints": (),
        "provenance": context.provenance(source_record_id),
        "first_imported_revision": context.revision,
        "last_verified_revision": context.revision,
        "status": "imported",
        "notes": "",
    }
    values.update(changes)
    record = CanonicalRecord(**values)
    return replace(record, id=stable_record_id(record))
