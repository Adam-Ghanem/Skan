from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from tools.corpus.external_layout import EXTERNAL_STORE_FILES
from tools.corpus.external_model import CanonicalRecord


def write_external_manifest(
    directory: Path,
    records_by_file: Mapping[str, Sequence[CanonicalRecord]],
) -> bytes:
    expected = set(EXTERNAL_STORE_FILES)
    actual = set(records_by_file)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(
            "records_by_file must contain the exact external store set "
            f"(missing={missing}, unexpected={unexpected})"
        )

    stores: dict[str, object] = {}
    for name in EXTERNAL_STORE_FILES:
        records = records_by_file[name]
        store_bytes = (directory / name).read_bytes()
        kinds = Counter(record.kind for record in records)
        stores[name] = {
            "count": len(records),
            "kinds": dict(sorted(kinds.items())),
            "sha256": "sha256:" + hashlib.sha256(store_bytes).hexdigest(),
        }

    manifest = {"schema_version": 1, "stores": stores}
    manifest_bytes = (
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        + b"\n"
    )
    (directory / "manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes
