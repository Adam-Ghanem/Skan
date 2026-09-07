from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Mapping

from tools.corpus.io import write_jsonl
from tools.corpus.model import CanonicalRecord, validate_record
from tools.corpus.runtime_os_db import emit_os_db, parse_os_db
from tools.corpus.runtime_service_db import emit_service_db, parse_service_db
from tools.corpus.runtime_udp_db import emit_udp_db, parse_udp_db
from tools.corpus.sources import SourcePolicy, load_source_manifest


_RUNTIME_FILES = (
    "data/service-probes.db",
    "data/udp-probes.db",
    "data/os-fingerprints.db",
    "data/os-fingerprints-v6.db",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_records(
    records: list[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
) -> None:
    for record in records:
        errors = validate_record(record, sources)
        if errors:
            raise ValueError(
                f"invalid migrated record {record.id or '<unassigned>'}: {'; '.join(errors)}"
            )
        for contribution in record.provenance:
            source = sources.get(contribution.source_id)
            if source is None:
                raise ValueError(f"unknown migration source {contribution.source_id}")
            if not source.redistribution_allowed:
                raise ValueError(
                    f"source {source.id} does not allow redistribution"
                )
            if record.kind in source.blocked_data_classes:
                raise ValueError(
                    f"source {source.id} is blocked for data class {record.kind}"
                )
            if record.kind not in source.approved_data_classes:
                raise ValueError(
                    f"source {source.id} is not approved for data class {record.kind}"
                )


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _require_same(
    label: str,
    expected: list[CanonicalRecord],
    actual: list[CanonicalRecord],
) -> None:
    if actual != expected:
        expected_ids = [record.id for record in expected]
        actual_ids = [record.id for record in actual]
        raise ValueError(
            f"{label} round-trip mismatch: expected ids {expected_ids}, got {actual_ids}"
        )


def migrate_first_party(root: Path, output_root: Path) -> dict[str, object]:
    root = root.resolve()
    output_root = output_root.resolve()

    sources = load_source_manifest(root / "corpus" / "sources" / "sources.json")
    first_party = sources.get("skan-first-party")
    if first_party is None:
        raise ValueError("source manifest is missing skan-first-party")
    if not first_party.redistribution_allowed:
        raise ValueError("skan-first-party does not allow redistribution")

    service_records = parse_service_db(root / "data" / "service-probes.db")
    udp_records = parse_udp_db(root / "data" / "udp-probes.db")
    os_ipv4_records = parse_os_db(root / "data" / "os-fingerprints.db", "ipv4")
    os_ipv6_records = parse_os_db(root / "data" / "os-fingerprints-v6.db", "ipv6")

    all_records = (
        service_records
        + udp_records
        + os_ipv4_records
        + os_ipv6_records
    )
    _validate_records(all_records, sources)

    canonical_dir = output_root / "corpus" / "canonical"
    write_jsonl(canonical_dir / "services.jsonl", service_records)
    write_jsonl(canonical_dir / "udp.jsonl", udp_records)
    write_jsonl(canonical_dir / "os.jsonl", os_ipv4_records + os_ipv6_records)
    write_jsonl(canonical_dir / "products.jsonl", [])

    generated_paths = {
        "data/service-probes.db": output_root / "data" / "service-probes.db",
        "data/udp-probes.db": output_root / "data" / "udp-probes.db",
        "data/os-fingerprints.db": output_root / "data" / "os-fingerprints.db",
        "data/os-fingerprints-v6.db": output_root / "data" / "os-fingerprints-v6.db",
    }
    _write_text(generated_paths["data/service-probes.db"], emit_service_db(service_records))
    _write_text(generated_paths["data/udp-probes.db"], emit_udp_db(udp_records))
    _write_text(generated_paths["data/os-fingerprints.db"], emit_os_db(os_ipv4_records))
    _write_text(generated_paths["data/os-fingerprints-v6.db"], emit_os_db(os_ipv6_records))

    regenerated_service = parse_service_db(generated_paths["data/service-probes.db"])
    regenerated_udp = parse_udp_db(generated_paths["data/udp-probes.db"])
    regenerated_os_ipv4 = parse_os_db(generated_paths["data/os-fingerprints.db"], "ipv4")
    regenerated_os_ipv6 = parse_os_db(generated_paths["data/os-fingerprints-v6.db"], "ipv6")

    _require_same("service", service_records, regenerated_service)
    _require_same("udp", udp_records, regenerated_udp)
    _require_same("os ipv4", os_ipv4_records, regenerated_os_ipv4)
    _require_same("os ipv6", os_ipv6_records, regenerated_os_ipv6)

    return {
        "service_records": len(service_records),
        "udp_records": len(udp_records),
        "os_ipv4_records": len(os_ipv4_records),
        "os_ipv6_records": len(os_ipv6_records),
        "roundtrip_verified": True,
        "sha256": {
            relative: _sha256(path)
            for relative, path in sorted(generated_paths.items())
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Migrate Skan first-party runtime fingerprint databases into canonical form"
    )
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify migration in a temporary directory without mutating the repository",
    )
    mode.add_argument(
        "--output",
        type=Path,
        help="write generated canonical and runtime artifacts to this directory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.check:
            with tempfile.TemporaryDirectory(prefix="skan-corpus-roundtrip-") as temp:
                summary = migrate_first_party(args.root, Path(temp))
        else:
            assert args.output is not None
            summary = migrate_first_party(args.root, args.output)
    except (OSError, ValueError) as exc:
        print(f"first-party corpus migration failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
