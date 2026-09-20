from __future__ import annotations

import argparse
import json
from pathlib import Path
import resource
import sys
import time
from typing import Any

from tools.corpus.validate import validate_root


_RUNTIME_FILES = (
    "data/service-probes.db",
    "data/udp-probes.db",
    "data/os-fingerprints.db",
    "data/os-fingerprints-v6.db",
)


def _total_bytes(paths: list[Path]) -> int:
    return sum(path.stat().st_size for path in paths if path.is_file())


def _peak_rss_mib() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return value / (1024.0 * 1024.0)
    return value / 1024.0


def measure_corpus(root: Path) -> dict[str, Any]:
    root = root.resolve()
    canonical_files = sorted((root / "corpus/canonical").glob("*.jsonl"))
    canonical_bytes = _total_bytes(canonical_files)
    runtime_paths = [root / relative for relative in _RUNTIME_FILES]
    runtime_bytes = _total_bytes(runtime_paths)

    started = time.perf_counter()
    summary = validate_root(root)
    load_seconds = time.perf_counter() - started

    report: dict[str, Any] = {
        "canonical_bytes": canonical_bytes,
        "canonical_mib": canonical_bytes / (1024.0 * 1024.0),
        "first_party_runtime_bytes": runtime_bytes,
        "first_party_runtime_mib": runtime_bytes / (1024.0 * 1024.0),
        "load_seconds": load_seconds,
        "peak_rss_mib": _peak_rss_mib(),
        "total_records": int(summary.get("total_records", 0)),
        "detection_records": int(summary.get("detection_records", 0)),
        "metadata_records": int(summary.get("metadata_records", 0)),
        "unresolved_conflicts": int(summary.get("conflict_count", 0)),
        "records_by_kind": summary.get("records_by_kind", {}),
        "records_by_source": summary.get("records_by_source", {}),
    }

    nvd_report_path = root / "corpus/reports/nvd-cpe-stats.json"
    if nvd_report_path.is_file():
        raw = json.loads(nvd_report_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            report["nvd_cpe"] = {
                key: raw[key]
                for key in (
                    "sqlite_rows",
                    "active_rows",
                    "distinct_vendors",
                    "distinct_products",
                    "sqlite_bytes",
                    "sqlite_sha256",
                    "byte_deterministic_regeneration",
                )
                if key in raw
            }
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Measure Skan corpus resource usage")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--max-load-seconds", type=float)
    parser.add_argument("--max-peak-rss-mib", type=float)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        report = measure_corpus(args.root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"corpus performance measurement failed: {exc}", file=sys.stderr)
        return 1

    failures: list[str] = []
    if args.max_load_seconds is not None and report["load_seconds"] > args.max_load_seconds:
        failures.append(
            f"load_seconds {report['load_seconds']:.3f} > {args.max_load_seconds:.3f}"
        )
    if args.max_peak_rss_mib is not None and report["peak_rss_mib"] > args.max_peak_rss_mib:
        failures.append(
            f"peak_rss_mib {report['peak_rss_mib']:.1f} > {args.max_peak_rss_mib:.1f}"
        )

    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    if failures:
        print("corpus performance gate failed: " + "; ".join(failures), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
