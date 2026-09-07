from __future__ import annotations

from collections import Counter
from typing import Iterable

from tools.corpus.model import CanonicalRecord


def corpus_stats(
    records: Iterable[CanonicalRecord],
    *,
    conflict_count: int,
) -> dict[str, object]:
    materialized = list(records)
    kinds = Counter(record.kind for record in materialized)
    statuses = Counter(record.status for record in materialized)
    sources: Counter[str] = Counter()
    records_with_cpe = 0

    for record in materialized:
        if record.cpe:
            records_with_cpe += 1
        source_ids = {item.source_id for item in record.provenance}
        for source_id in source_ids:
            sources[source_id] += 1

    return {
        "total_records": len(materialized),
        "records_by_kind": dict(sorted(kinds.items())),
        "records_by_status": dict(sorted(statuses.items())),
        "records_by_source": dict(sorted(sources.items())),
        "records_with_cpe": records_with_cpe,
        "conflict_count": conflict_count,
    }
