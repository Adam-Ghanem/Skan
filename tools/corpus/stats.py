from __future__ import annotations

from collections import Counter
from typing import Iterable

from tools.corpus.model import CanonicalRecord


_DETECTION_KINDS = {"service_matcher", "active_probe", "os_fingerprint", "udp_probe", "web_fingerprint", "device_fingerprint"}


def corpus_stats(
    records: Iterable[CanonicalRecord],
    *,
    conflict_count: int,
    unresolved_conflict_count: int = 0,
) -> dict[str, object]:
    materialized = list(records)
    kinds = Counter(record.kind for record in materialized)
    statuses = Counter(record.status for record in materialized)
    sources: Counter[str] = Counter()
    records_with_cpe = 0
    for record in materialized:
        if record.cpe:
            records_with_cpe += 1
        for source_id in {item.source_id for item in record.provenance}:
            sources[source_id] += 1
    detection_records = sum(1 for record in materialized if record.kind in _DETECTION_KINDS)
    return {
        "total_records": len(materialized),
        "detection_records": detection_records,
        "metadata_records": len(materialized) - detection_records,
        "suppressed_records": int(statuses.get("suppressed", 0)),
        "records_by_kind": dict(sorted(kinds.items())),
        "records_by_status": dict(sorted(statuses.items())),
        "records_by_source": dict(sorted(sources.items())),
        "records_with_cpe": records_with_cpe,
        "conflict_count": conflict_count,
        "unresolved_conflicts": unresolved_conflict_count,
    }
