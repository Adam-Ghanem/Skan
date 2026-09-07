from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from tools.corpus.dedupe import Conflict, merge_records
from tools.corpus.io import load_jsonl
from tools.corpus.model import CanonicalRecord
from tools.corpus.snapshots import verify_snapshot
from tools.corpus.sources import SourcePolicy, load_source_manifest
from tools.corpus.stats import corpus_stats


_CORE_CANONICAL_FILES = (
    "services.jsonl",
    "os.jsonl",
    "udp.jsonl",
    "products.jsonl",
)
_OPTIONAL_EXTERNAL_FILES = (
    "web.jsonl",
    "devices.jsonl",
    "registry.jsonl",
    "cpe.jsonl",
)
_OVERRIDE_FILES = ("aliases.json", "conflicts.json", "suppressions.json")


def _load_override_object(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid override {path.name}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"invalid override {path.name}: root must be an object")
    return parsed


def _validate_source_data_classes(records: list[CanonicalRecord], sources: dict[str, SourcePolicy]) -> None:
    for record in records:
        for provenance in record.provenance:
            source = sources.get(provenance.source_id)
            if source is None:
                raise ValueError(f"unknown source_id: {provenance.source_id}")
            if not source.redistribution_allowed:
                raise ValueError(f"source {source.id} does not allow redistribution")
            if record.kind in source.blocked_data_classes:
                raise ValueError(f"source {source.id} is blocked for data class {record.kind}")
            if record.kind not in source.approved_data_classes:
                raise ValueError(f"source {source.id} is not approved for data class {record.kind}")


def _verify_pinned_snapshots(root: Path, sources: dict[str, SourcePolicy]) -> None:
    for source_id, source in sorted(sources.items()):
        if source.expected_hash is None:
            continue
        snapshot = root / "corpus" / "snapshots" / source_id / "source"
        if not snapshot.is_file():
            raise ValueError(f"missing pinned snapshot for source {source_id}: {snapshot}")
        verify_snapshot(snapshot, source.expected_hash)


def _conflict_pair_key(conflict: Conflict) -> str:
    return "|".join(sorted((conflict.left_id, conflict.right_id)))


def _is_resolved(conflict: Conflict, overrides: dict[str, Any]) -> bool:
    entry = overrides.get(_conflict_pair_key(conflict))
    return isinstance(entry, dict) and isinstance(entry.get("resolution"), str) and bool(entry["resolution"].strip())


def _load_canonical_file(
    path: Path,
    name: str,
    sources: dict[str, SourcePolicy],
    *,
    required: bool,
) -> list[CanonicalRecord]:
    if not path.is_file():
        if required:
            return load_jsonl(path, sources)
        return []
    return load_jsonl(path, sources)


def validate_root(root: Path) -> dict[str, object]:
    root = root.resolve()
    sources = load_source_manifest(root / "corpus/sources/sources.json")
    override_dir = root / "corpus/overrides"
    overrides = {name: _load_override_object(override_dir / name) for name in _OVERRIDE_FILES}
    records: list[CanonicalRecord] = []
    seen_ids: dict[str, str] = {}
    canonical_dir = root / "corpus/canonical"

    for name in _CORE_CANONICAL_FILES + _OPTIONAL_EXTERNAL_FILES:
        file_records = _load_canonical_file(
            canonical_dir / name,
            name,
            sources,
            required=name in _CORE_CANONICAL_FILES,
        )
        for record in file_records:
            previous_file = seen_ids.get(record.id)
            if previous_file is not None:
                raise ValueError(
                    f"duplicate canonical id across corpus files: {record.id} "
                    f"appears in {previous_file} and {name}"
                )
            seen_ids[record.id] = name
        records.extend(file_records)

    _validate_source_data_classes(records, sources)
    _verify_pinned_snapshots(root, sources)
    merged, conflicts = merge_records(records)
    conflict_overrides = overrides["conflicts.json"]
    unresolved = [conflict for conflict in conflicts if not _is_resolved(conflict, conflict_overrides)]
    if unresolved:
        rendered = ", ".join(
            f"{c.left_id}|{c.right_id} ({','.join(c.differing_fields)})" for c in unresolved
        )
        raise ValueError(f"unresolved corpus conflict: {rendered}")
    return corpus_stats(merged, conflict_count=len(conflicts))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Skan fingerprint corpus")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        summary = validate_root(args.root)
    except (OSError, ValueError) as exc:
        print(f"corpus validation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
