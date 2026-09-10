from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.legacy_udp import (
    compile_legacy_udp,
    load_legacy_udp,
    verify_udp_round_trip,
)
from tools.corpus.sources import load_source_manifest


def _atomic_write_text(path: Path, text: str) -> None:
    encoded = text.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def build_udp_artifacts(
    *,
    legacy_path: Path,
    manifest_path: Path,
    canonical_path: Path,
    runtime_path: Path,
) -> int:
    """Build and verify the UDP canonical/runtime vertical slice.

    Verification is intentionally performed after both serialization boundaries:
    legacy runtime text -> canonical records -> JSONL reload -> generated runtime
    text -> legacy semantic reload. The C++ loader gate is a separate integration
    test that consumes ``runtime_path``.
    """

    sources = load_source_manifest(manifest_path)
    migrated = load_legacy_udp(legacy_path, sources)

    write_jsonl(canonical_path, migrated, sources)
    canonical = load_jsonl(
        canonical_path,
        sources,
        expected_kind="udp_probe",
    )
    verify_udp_round_trip(migrated, canonical)

    runtime_text = compile_legacy_udp(canonical, sources)
    _atomic_write_text(runtime_path, runtime_text)
    generated = load_legacy_udp(runtime_path, sources)
    verify_udp_round_trip(canonical, generated)

    if runtime_text != compile_legacy_udp(canonical, sources):
        raise RuntimeError("UDP runtime compiler is non-deterministic")
    return len(canonical)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the Intelligence DB v2 UDP canonical and runtime artifacts."
    )
    parser.add_argument("--legacy", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    count = build_udp_artifacts(
        legacy_path=arguments.legacy,
        manifest_path=arguments.sources,
        canonical_path=arguments.canonical,
        runtime_path=arguments.runtime,
    )
    print(f"verified {count} UDP canonical records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
