from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.legacy_os import (
    LegacyOSError,
    compile_legacy_os,
    load_legacy_os,
    verify_os_round_trip,
)
from tools.corpus.model import OSFingerprintSemantics
from tools.corpus.sources import load_source_manifest


_MAXIMUM_COMBINED_FINGERPRINTS = 256


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


def _assert_global_runtime_ids(records: tuple[object, ...]) -> None:
    runtime_ids: set[str] = set()
    for record in records:
        body = getattr(record, "body", None)
        if not isinstance(body, OSFingerprintSemantics):
            raise LegacyOSError("combined OS corpus contains a non-OS record")
        if body.runtime_id in runtime_ids:
            raise LegacyOSError(
                f"duplicate runtime fingerprint ID across address families: {body.runtime_id}"
            )
        runtime_ids.add(body.runtime_id)


def build_os_artifacts(
    *,
    legacy_ipv4_path: Path,
    legacy_ipv6_path: Path,
    manifest_path: Path,
    canonical_path: Path,
    runtime_ipv4_path: Path,
    runtime_ipv6_path: Path,
) -> int:
    """Build and verify the dual-stack Intelligence DB v2 OS vertical slice."""

    sources = load_source_manifest(manifest_path)
    migrated_ipv4 = load_legacy_os(
        legacy_ipv4_path, sources, expected_family="ipv4"
    )
    migrated_ipv6 = load_legacy_os(
        legacy_ipv6_path, sources, expected_family="ipv6"
    )
    migrated = (*migrated_ipv4, *migrated_ipv6)
    if len(migrated) > _MAXIMUM_COMBINED_FINGERPRINTS:
        raise LegacyOSError(
            f"combined OS corpus exceeds {_MAXIMUM_COMBINED_FINGERPRINTS} fingerprints"
        )
    _assert_global_runtime_ids(migrated)

    write_jsonl(canonical_path, migrated, sources)
    canonical = load_jsonl(
        canonical_path,
        sources,
        expected_kind="os_fingerprint",
    )
    verify_os_round_trip(migrated, canonical)
    _assert_global_runtime_ids(canonical)

    canonical_ipv4 = tuple(
        record
        for record in canonical
        if isinstance(record.body, OSFingerprintSemantics)
        and record.body.address_family == "ipv4"
    )
    canonical_ipv6 = tuple(
        record
        for record in canonical
        if isinstance(record.body, OSFingerprintSemantics)
        and record.body.address_family == "ipv6"
    )
    if len(canonical_ipv4) + len(canonical_ipv6) != len(canonical):
        raise LegacyOSError("canonical OS corpus contains an unsupported address family")

    runtime_ipv4 = compile_legacy_os(
        canonical_ipv4, sources, address_family="ipv4"
    )
    runtime_ipv6 = compile_legacy_os(
        canonical_ipv6, sources, address_family="ipv6"
    )
    _atomic_write_text(runtime_ipv4_path, runtime_ipv4)
    _atomic_write_text(runtime_ipv6_path, runtime_ipv6)

    generated_ipv4 = load_legacy_os(
        runtime_ipv4_path, sources, expected_family="ipv4"
    )
    generated_ipv6 = load_legacy_os(
        runtime_ipv6_path, sources, expected_family="ipv6"
    )
    verify_os_round_trip(canonical_ipv4, generated_ipv4)
    verify_os_round_trip(canonical_ipv6, generated_ipv6)

    if runtime_ipv4 != compile_legacy_os(
        canonical_ipv4, sources, address_family="ipv4"
    ):
        raise RuntimeError("IPv4 OS runtime compiler is non-deterministic")
    if runtime_ipv6 != compile_legacy_os(
        canonical_ipv6, sources, address_family="ipv6"
    ):
        raise RuntimeError("IPv6 OS runtime compiler is non-deterministic")
    return len(canonical)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build Intelligence DB v2 IPv4/IPv6 OS canonical and runtime artifacts."
    )
    parser.add_argument("--legacy-ipv4", type=Path, required=True)
    parser.add_argument("--legacy-ipv6", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--runtime-ipv4", type=Path, required=True)
    parser.add_argument("--runtime-ipv6", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    count = build_os_artifacts(
        legacy_ipv4_path=arguments.legacy_ipv4,
        legacy_ipv6_path=arguments.legacy_ipv6,
        manifest_path=arguments.sources,
        canonical_path=arguments.canonical,
        runtime_ipv4_path=arguments.runtime_ipv4,
        runtime_ipv6_path=arguments.runtime_ipv6,
    )
    print(f"verified {count} dual-stack OS canonical records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
