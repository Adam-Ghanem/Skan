from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from tools.corpus.dedupe import Conflict, merge_records
from tools.corpus.external_io import load_jsonl as load_external_jsonl
from tools.corpus.external_model import CanonicalRecord as ExternalCanonicalRecord
from tools.corpus.external_sources import (
    SourcePolicy as ExternalSourcePolicy,
    load_source_manifest as load_external_source_manifest,
)
from tools.corpus.io import load_jsonl as load_core_jsonl
from tools.corpus.sources import (
    SourcePolicy as CoreSourcePolicy,
    load_source_manifest as load_core_source_manifest,
)
from tools.corpus.snapshots import verify_snapshot


_CORE_CANONICAL_FILES = (
    "active-probes.jsonl",
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
_DETECTION_KINDS = {
    "service_matcher",
    "active_probe",
    "os_fingerprint",
    "udp_probe",
    "web_fingerprint",
    "device_fingerprint",
}
SourcePolicy = CoreSourcePolicy | ExternalSourcePolicy


def _load_override_object(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid override {path.name}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"invalid override {path.name}: root must be an object")
    return parsed


def _validate_source_data_classes(
    records: list[object],
    sources: Mapping[str, SourcePolicy],
) -> None:
    for record in records:
        kind = str(getattr(record, "kind"))
        for provenance in getattr(record, "provenance"):
            source = sources.get(provenance.source_id)
            if source is None:
                raise ValueError(f"unknown source_id: {provenance.source_id}")
            if not source.redistribution_allowed:
                raise ValueError(f"source {source.id} does not allow redistribution")
            if kind in source.blocked_data_classes:
                raise ValueError(f"source {source.id} is blocked for data class {kind}")
            if kind not in source.approved_data_classes:
                raise ValueError(f"source {source.id} is not approved for data class {kind}")


def _verify_pinned_snapshots(
    root: Path,
    sources: Mapping[str, SourcePolicy],
) -> None:
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
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("resolution"), str)
        and bool(entry["resolution"].strip())
    )


def _uses_core_schema(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    with path.open("r", encoding="utf-8") as handle:
        first_line = handle.readline()
    try:
        value = json.loads(first_line)
    except json.JSONDecodeError:
        return False
    return (
        isinstance(value, dict)
        and value.get("schema_version") == 2
        and isinstance(value.get("body"), dict)
    )


def _load_canonical_file(
    path: Path,
    *,
    required: bool,
    core_sources: Mapping[str, CoreSourcePolicy],
    external_sources: Mapping[str, ExternalSourcePolicy],
) -> tuple[list[object], list[ExternalCanonicalRecord]]:
    if not path.is_file():
        if not required:
            return [], []
        # Preserve the external loader's useful missing-file contract.
        load_external_jsonl(path, external_sources)
        raise AssertionError("unreachable")

    if _uses_core_schema(path):
        if not core_sources:
            raise ValueError(f"core source manifest is required for {path.name}")
        return list(load_core_jsonl(path, core_sources, allow_empty=True)), []

    external = load_external_jsonl(path, external_sources)
    return list(external), list(external)


def _stats(records: list[object], *, conflict_count: int) -> dict[str, object]:
    kinds = Counter(str(getattr(record, "kind")) for record in records)
    statuses = Counter(str(getattr(record, "status")) for record in records)
    sources: Counter[str] = Counter()
    records_with_cpe = 0
    for record in records:
        cpe = getattr(record, "cpe", None)
        if cpe is None:
            cpe = getattr(getattr(record, "body", None), "cpe", ())
        if cpe:
            records_with_cpe += 1
        for source_id in {item.source_id for item in getattr(record, "provenance")}:
            sources[source_id] += 1
    detection_records = sum(
        count for kind, count in kinds.items() if kind in _DETECTION_KINDS
    )
    return {
        "total_records": len(records),
        "detection_records": detection_records,
        "metadata_records": len(records) - detection_records,
        "suppressed_records": int(statuses.get("suppressed", 0)),
        "records_by_kind": dict(sorted(kinds.items())),
        "records_by_status": dict(sorted(statuses.items())),
        "records_by_source": dict(sorted(sources.items())),
        "records_with_cpe": records_with_cpe,
        "conflict_count": conflict_count,
        "unresolved_conflicts": 0,
    }


def validate_root(root: Path) -> dict[str, object]:
    root = root.resolve()
    source_dir = root / "corpus" / "sources"
    external_manifest = source_dir / "external-sources.json"
    if external_manifest.is_file():
        core_sources = load_core_source_manifest(source_dir / "sources.json")
        external_sources = load_external_source_manifest(external_manifest)
    else:
        core_sources = {}
        external_sources = load_external_source_manifest(source_dir / "sources.json")

    overrides = {
        name: _load_override_object(root / "corpus" / "overrides" / name)
        for name in _OVERRIDE_FILES
    }
    all_sources: dict[str, SourcePolicy] = dict(external_sources)
    all_sources.update(core_sources)

    records: list[object] = []
    external_records: list[ExternalCanonicalRecord] = []
    seen_ids: dict[str, str] = {}
    canonical_dir = root / "corpus" / "canonical"

    for name in _CORE_CANONICAL_FILES + _OPTIONAL_EXTERNAL_FILES:
        file_records, file_external = _load_canonical_file(
            canonical_dir / name,
            required=name in _CORE_CANONICAL_FILES and name != "active-probes.jsonl",
            core_sources=core_sources,
            external_sources=external_sources,
        )
        for record in file_records:
            record_id = str(getattr(record, "id"))
            previous_file = seen_ids.get(record_id)
            if previous_file is not None:
                raise ValueError(
                    f"duplicate canonical id across corpus files: {record_id} "
                    f"appears in {previous_file} and {name}"
                )
            seen_ids[record_id] = name
        records.extend(file_records)
        external_records.extend(file_external)

    _validate_source_data_classes(records, all_sources)
    _verify_pinned_snapshots(root, all_sources)
    _, conflicts = merge_records(external_records)
    conflict_overrides = overrides["conflicts.json"]
    unresolved = [
        conflict
        for conflict in conflicts
        if not _is_resolved(conflict, conflict_overrides)
    ]
    if unresolved:
        rendered = ", ".join(
            f"{item.left_id}|{item.right_id} ({','.join(item.differing_fields)})"
            for item in unresolved
        )
        raise ValueError(f"unresolved corpus conflict: {rendered}")
    return _stats(records, conflict_count=len(conflicts))


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
