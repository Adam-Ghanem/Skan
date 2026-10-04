from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from tools.corpus.attribution import render_notices
from tools.corpus.dedupe import merge_records
from tools.corpus.external_io import load_jsonl
from tools.corpus.external_layout import EXTERNAL_KIND_FILES, EXTERNAL_STORE_FILES
from tools.corpus.external_model import CanonicalRecord
from tools.corpus.external_sources import SourcePolicy, load_source_manifest


_MANIFEST_LIMIT = 128 * 1024
_STATISTICS_LIMIT = 1024 * 1024
_LOCK_LIMIT = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOCK_FIELDS = {
    "adapter_version",
    "attribution",
    "license_policy",
    "revision",
    "schema_version",
    "sha256",
    "source_id",
    "source_url",
}
_SUMMARY_FIELDS = (
    "total_records",
    "records_by_kind",
    "files",
    "detection_records",
    "port_registry_records",
    "conflict_count",
)
_DETECTION_KINDS = {
    "service_matcher",
    "active_probe",
    "os_fingerprint",
    "udp_probe",
    "web_fingerprint",
    "device_fingerprint",
}


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or unreadable") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file")


def _read_bytes(path: Path, label: str, limit: int | None = None) -> bytes:
    _regular_file(path, label)
    try:
        with path.open("rb") as handle:
            raw = handle.read() if limit is None else handle.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable") from exc
    if limit is not None and len(raw) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return raw


def _strict_json(
    path: Path,
    label: str,
    limit: int,
    *,
    canonical: bool = False,
) -> Any:
    raw = _read_bytes(path, label, limit)
    if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
        raise ValueError(f"{label} must end with LF")
    try:
        parsed = json.loads(
            raw[:-1].decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        detail = str(exc)
        if "duplicate JSON key" in detail or "non-finite JSON number" in detail:
            raise ValueError(f"{label}: {detail}") from exc
        raise ValueError(f"{label} is malformed JSON") from exc
    if canonical:
        expected = (
            json.dumps(
                parsed,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            + b"\n"
        )
        if raw != expected:
            raise ValueError(f"{label} is not canonically serialized")
    return parsed


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_manifest(directory: Path) -> dict[str, dict[str, Any]]:
    value = _require_object(
        _strict_json(
            directory / "manifest.json",
            "external manifest",
            _MANIFEST_LIMIT,
            canonical=True,
        ),
        "external manifest",
    )
    schema_version = value.get("schema_version")
    if (
        set(value) != {"schema_version", "stores"}
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise ValueError("external manifest has an invalid schema")
    stores = _require_object(value.get("stores"), "external manifest stores")
    if set(stores) != set(EXTERNAL_STORE_FILES):
        raise ValueError("external manifest does not contain the exact store set")
    result: dict[str, dict[str, Any]] = {}
    for name in EXTERNAL_STORE_FILES:
        entry = _require_object(stores[name], f"external manifest entry {name}")
        if set(entry) != {"count", "kinds", "sha256"}:
            raise ValueError(f"external manifest entry {name} has invalid fields")
        count = entry.get("count")
        kinds = entry.get("kinds")
        digest = entry.get("sha256")
        if type(count) is not int or count < 0:
            raise ValueError(f"external manifest entry {name} has invalid count")
        if not isinstance(kinds, dict) or any(
            not isinstance(kind, str) or type(amount) is not int or amount < 0
            for kind, amount in kinds.items()
        ):
            raise ValueError(f"external manifest entry {name} has invalid kinds")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or _SHA256.fullmatch(digest.removeprefix("sha256:")) is None
        ):
            raise ValueError(f"external manifest entry {name} has invalid sha256")
        result[name] = entry
    return result


def _validate_inventory(directory: Path) -> None:
    if directory.is_symlink():
        raise ValueError("external corpus directory must not be a symlink")
    if not directory.is_dir():
        raise ValueError("external corpus directory is missing")
    expected = set(EXTERNAL_STORE_FILES) | {"manifest.json"}
    try:
        entries = {entry.name: entry for entry in directory.iterdir()}
    except OSError as exc:
        raise ValueError("external corpus directory is unreadable") from exc
    unexpected = sorted(set(entries) - expected)
    if unexpected:
        raise ValueError(f"external corpus has unexpected entry: {unexpected[0]}")
    missing = sorted(expected - set(entries))
    if missing:
        raise ValueError(f"external store is missing: {missing[0]}")
    for name in EXTERNAL_STORE_FILES:
        _regular_file(entries[name], f"external store {name}")


def _load_records(
    directory: Path,
    sources: Mapping[str, SourcePolicy],
    manifest: Mapping[str, Mapping[str, Any]],
) -> tuple[list[CanonicalRecord], dict[str, int]]:
    records: list[CanonicalRecord] = []
    seen_ids: set[str] = set()
    file_counts: dict[str, int] = {}
    for name in EXTERNAL_STORE_FILES:
        path = directory / name
        raw = _read_bytes(path, f"external store {name}")
        try:
            loaded = load_jsonl(path, sources)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"external store {name} is invalid: {exc}") from exc
        misplaced = next(
            (
                record
                for record in loaded
                if EXTERNAL_KIND_FILES.get(record.kind) != name
            ),
            None,
        )
        if misplaced is not None:
            raise ValueError(
                f"external record kind {misplaced.kind} is stored in {name}"
            )
        duplicate = next((record.id for record in loaded if record.id in seen_ids), None)
        if duplicate is not None:
            raise ValueError(f"duplicate external record id across stores: {duplicate}")
        seen_ids.update(record.id for record in loaded)
        records.extend(loaded)
        file_counts[name] = len(loaded)

        expected = manifest[name]
        actual_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        if expected["sha256"] != actual_hash:
            raise ValueError(f"external manifest entry {name} sha256 does not match store")
        if expected["count"] != len(loaded):
            raise ValueError(f"external manifest entry {name} count does not match store")
        actual_kinds = dict(sorted(Counter(record.kind for record in loaded).items()))
        if expected["kinds"] != actual_kinds:
            raise ValueError(f"external manifest entry {name} kinds do not match store")

    _, conflicts = merge_records(records)
    if conflicts:
        first = conflicts[0]
        raise ValueError(
            "unresolved external corpus conflict: "
            f"{first.left_id}|{first.right_id}"
        )
    return records, file_counts


def _summary(records: list[CanonicalRecord], files: dict[str, int]) -> dict[str, object]:
    kinds = Counter(record.kind for record in records)
    return {
        "conflict_count": 0,
        "detection_records": sum(
            1 for record in records if record.kind in _DETECTION_KINDS
        ),
        "files": {name: files[name] for name in EXTERNAL_STORE_FILES},
        "port_registry_records": sum(
            1 for record in records if record.kind == "port_registry"
        ),
        "records_by_kind": dict(sorted(kinds.items())),
        "total_records": len(records),
    }


def _same_json_value(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _same_json_value(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json_value(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected, strict=True)
        )
    return actual == expected


def _verify_statistics(path: Path, expected: Mapping[str, object]) -> None:
    statistics = _require_object(
        _strict_json(path, "external statistics", _STATISTICS_LIMIT),
        "external statistics",
    )
    for field in _SUMMARY_FIELDS:
        if field not in statistics:
            raise ValueError(f"external statistics is missing {field}")
        if not _same_json_value(statistics[field], expected[field]):
            raise ValueError(f"external statistics {field} does not match stores")


def _validate_lock_shape(value: Any, path: Path) -> dict[str, Any]:
    lock = _require_object(value, f"source lock {path.name}")
    if set(lock) != _LOCK_FIELDS:
        raise ValueError(f"source lock {path.name} has invalid fields")
    if lock.get("schema_version") != 1 or type(lock.get("schema_version")) is not int:
        raise ValueError(f"source lock {path.name} has invalid schema_version")
    if type(lock.get("adapter_version")) is not int or lock["adapter_version"] < 1:
        raise ValueError(f"source lock {path.name} has invalid adapter_version")
    for field in ("source_id", "revision", "source_url", "license_policy", "attribution"):
        if not isinstance(lock.get(field), str):
            raise ValueError(f"source lock {path.name} has invalid {field}")
    if not isinstance(lock.get("sha256"), str) or _SHA256.fullmatch(lock["sha256"]) is None:
        raise ValueError(f"source lock {path.name} has invalid sha256")
    if path.stem != lock["source_id"]:
        raise ValueError(
            f"source lock {path.name} is used under the wrong filename for {lock['source_id']}"
        )
    return lock


def _load_locks(directory: Path) -> dict[str, dict[str, Any]]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("source lock directory is missing or unsafe")
    locks: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json":
            continue
        lock = _validate_lock_shape(
            _strict_json(path, f"source lock {path.name}", _LOCK_LIMIT), path
        )
        source_id = lock["source_id"]
        if source_id in locks:
            raise ValueError(f"source {source_id} has more than one lock")
        locks[source_id] = lock
    return locks


def _verify_provenance(
    records: list[CanonicalRecord],
    locks: Mapping[str, Mapping[str, Any]],
) -> None:
    represented = {
        item.source_id
        for record in records
        for item in record.provenance
        if item.source_id != "skan-first-party"
    }
    for source_id in sorted(represented):
        lock = locks.get(source_id)
        if lock is None:
            raise ValueError(f"represented source {source_id} is missing its source lock")
        for record in records:
            for item in record.provenance:
                if item.source_id != source_id:
                    continue
                comparisons = {
                    "revision": item.source_revision,
                    "source_url": item.source_url,
                    "license_policy": item.source_license,
                    "sha256": item.source_hash.removeprefix("sha256:"),
                }
                for field, expected in comparisons.items():
                    if lock[field] != expected:
                        raise ValueError(
                            f"source {source_id} lock {field} does not match provenance"
                        )


def verify_external_repository(root: Path) -> dict[str, object]:
    root = Path(root)
    external = root / "corpus/external"
    _validate_inventory(external)
    manifest = _load_manifest(external)
    try:
        sources = load_source_manifest(root / "corpus/sources/external-sources.json")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"external source policy is invalid: {exc}") from exc

    records, files = _load_records(external, sources, manifest)
    summary = _summary(records, files)
    _verify_statistics(root / "corpus/reports/external-stats.json", summary)
    locks = _load_locks(root / "corpus/locks")
    _verify_provenance(records, locks)

    notices_path = root / "corpus/THIRD_PARTY_NOTICES.md"
    actual_notices = _read_bytes(notices_path, "third-party notices")
    expected_notices = render_notices(records, sources).encode("utf-8")
    if actual_notices != expected_notices:
        raise ValueError("third-party notices do not match represented sources")
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Skan's committed external corpus generation"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        summary = verify_external_repository(arguments.root)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"external corpus verification failed: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
