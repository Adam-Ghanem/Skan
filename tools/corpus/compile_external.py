from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping

from tools.corpus.dedupe import merge_records
from tools.corpus.io import write_jsonl
from tools.corpus.model import CanonicalRecord, validate_record
from tools.corpus.sources import SourcePolicy


_KIND_FILES = {
    "service_matcher": "services.jsonl",
    "active_probe": "services.jsonl",
    "os_fingerprint": "os.jsonl",
    "udp_probe": "udp.jsonl",
    "web_fingerprint": "web.jsonl",
    "device_fingerprint": "devices.jsonl",
    "port_registry": "registry.jsonl",
    "product_record": "products.jsonl",
    "product_alias": "products.jsonl",
    "product_vocab": "products.jsonl",
    "registry": "products.jsonl",
    "cpe_record": "cpe.jsonl",
}
_ALL_FILES = tuple(sorted(set(_KIND_FILES.values())))


def compile_records(
    records: Iterable[CanonicalRecord],
    output_dir: Path,
    sources: Mapping[str, SourcePolicy],
) -> dict[str, object]:
    materialized = list(records)
    for record in materialized:
        errors = validate_record(record, sources)
        if errors:
            raise ValueError(f"invalid external record {record.id}: {'; '.join(errors)}")
        if record.kind not in _KIND_FILES:
            raise ValueError(f"no external output group for kind: {record.kind}")

    merged, conflicts = merge_records(materialized)
    if conflicts:
        rendered = ", ".join(f"{item.left_id}|{item.right_id}" for item in conflicts)
        raise ValueError(f"unresolved external corpus conflict: {rendered}")

    grouped: dict[str, list[CanonicalRecord]] = {name: [] for name in _ALL_FILES}
    for record in merged:
        grouped[_KIND_FILES[record.kind]].append(record)

    output_dir.mkdir(parents=True, exist_ok=True)
    for name in _ALL_FILES:
        write_jsonl(output_dir / name, grouped[name])

    counts = Counter(record.kind for record in merged)
    return {
        "total_records": len(merged),
        "records_by_kind": dict(sorted(counts.items())),
        "files": {name: len(grouped[name]) for name in _ALL_FILES},
        "conflict_count": 0,
    }
