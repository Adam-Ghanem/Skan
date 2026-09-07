from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Callable

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.iana_services import parse_iana_csv
from tools.corpus.adapters.nvd_cpe import parse_nvd_cpe_json
from tools.corpus.adapters.recog import parse_recog_xml
from tools.corpus.adapters.wappalyzer import parse_wappalyzer_json
from tools.corpus.benchmark import Observation, benchmark, better_than_nmap_gate, parse_nmap_xml
from tools.corpus.bulk_refresh import refresh_detection_sources
from tools.corpus.io import write_jsonl
from tools.corpus.model import CanonicalRecord
from tools.corpus.refresh import refresh_from_snapshot
from tools.corpus.source_lock import SourceLock, load_source_lock
from tools.corpus.validate import validate_root


_REQUIRED_BENCHMARK_METADATA = (
    "target_set",
    "skan_version",
    "nmap_version",
    "skan_command",
    "nmap_command",
)


def _add_root(command: argparse.ArgumentParser) -> None:
    command.add_argument("--root", type=Path, default=Path("."))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skan-corpus", description="Skan fingerprint corpus tools")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="validate the local canonical corpus")
    _add_root(verify)

    stats = sub.add_parser("stats", help="emit machine-readable local corpus statistics")
    _add_root(stats)

    import_cmd = sub.add_parser("import", help="build a corpus from local source snapshots")
    _add_root(import_cmd)
    import_cmd.add_argument("--recog-dir", type=Path, required=True)
    import_cmd.add_argument("--iana-csv", type=Path, required=True)
    import_cmd.add_argument("--wappalyzer-json", type=Path, required=True)
    import_cmd.add_argument("--output-root", type=Path, required=True)
    import_cmd.add_argument("--dry-run", action="store_true")

    benchmark_cmd = sub.add_parser("benchmark", help="compare truth-labelled Skan and Nmap observations")
    benchmark_cmd.add_argument("--truth-json", type=Path, required=True)
    benchmark_cmd.add_argument("--skan-json", type=Path, required=True)
    benchmark_cmd.add_argument("--nmap-xml", type=Path, required=True)
    benchmark_cmd.add_argument("--metadata-json", type=Path, required=True)

    refresh = sub.add_parser("refresh-from-snapshot", help="verify and adapt one pinned local snapshot")
    refresh.add_argument("--snapshot", type=Path, required=True)
    refresh.add_argument("--lock", type=Path, required=True)
    refresh.add_argument(
        "--adapter",
        choices=("iana-services", "nvd-cpe", "rapid7-recog", "wappalyzergo"),
        required=True,
    )
    refresh.add_argument("--output", type=Path, required=True)
    refresh.add_argument("--dry-run", action="store_true")
    return parser


def _lock_context(lock: SourceLock) -> AdapterContext:
    return AdapterContext(
        source_id=lock.source_id,
        revision=lock.revision,
        source_url=lock.source_url,
        source_license=lock.license_policy,
        source_hash=f"sha256:{lock.sha256}",
    )


def _snapshot_adapter(name: str) -> Callable[[Path, SourceLock], list[CanonicalRecord]]:
    def adapt(path: Path, lock: SourceLock) -> list[CanonicalRecord]:
        if lock.source_id != name:
            raise ValueError(f"source lock {lock.source_id} does not match adapter {name}")
        text = path.read_text(encoding="utf-8")
        context = _lock_context(lock)
        if name == "iana-services":
            return parse_iana_csv(text, context)
        if name == "nvd-cpe":
            return parse_nvd_cpe_json(text, context)
        if name == "rapid7-recog":
            return parse_recog_xml(text, context, source_path=path.name)
        if name == "wappalyzergo":
            return parse_wappalyzer_json(text, context)
        raise ValueError(f"unsupported snapshot adapter: {name}")

    return adapt


def _load_observations(path: Path) -> dict[str, Observation]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"observation JSON root must be an object: {path}")
    observations: dict[str, Observation] = {}
    for target_id, item in raw.items():
        if not isinstance(target_id, str) or not target_id:
            raise ValueError(f"observation target id must be a non-empty string: {path}")
        if not isinstance(item, dict):
            raise ValueError(f"observation {target_id} must be an object")
        values: dict[str, str | None] = {}
        for field in ("service", "product", "version", "os_family", "device_type"):
            value = item.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"observation {target_id}.{field} must be a string or null")
            values[field] = value
        observations[target_id] = Observation(
            target_id=target_id,
            service=values["service"],
            product=values["product"],
            version=values["version"],
            os_family=values["os_family"],
            device_type=values["device_type"],
        )
    return observations


def _load_benchmark_metadata(path: Path) -> tuple[dict[str, object], bool]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("benchmark metadata root must be an object")
    complete = all(isinstance(raw.get(key), str) and bool(str(raw[key]).strip()) for key in _REQUIRED_BENCHMARK_METADATA)
    return raw, complete


def _run_import(args: argparse.Namespace) -> dict[str, object]:
    if args.dry_run:
        with tempfile.TemporaryDirectory(prefix="skan-corpus-import-") as tmp:
            summary = refresh_detection_sources(
                repo_root=args.root,
                recog_dir=args.recog_dir,
                iana_csv=args.iana_csv,
                wappalyzer_json=args.wappalyzer_json,
                output_root=Path(tmp) / "generated",
            )
        return {**summary, "dry_run": True}
    summary = refresh_detection_sources(
        repo_root=args.root,
        recog_dir=args.recog_dir,
        iana_csv=args.iana_csv,
        wappalyzer_json=args.wappalyzer_json,
        output_root=args.output_root,
    )
    return {**summary, "dry_run": False, "output_root": str(args.output_root)}


def _run_refresh(args: argparse.Namespace) -> dict[str, object]:
    lock = load_source_lock(args.lock)
    result = refresh_from_snapshot(args.snapshot, lock, _snapshot_adapter(args.adapter))
    if not args.dry_run:
        write_jsonl(args.output, result.records)
    return {
        "source_id": result.source_id,
        "revision": result.revision,
        "record_count": result.record_count,
        "dry_run": bool(args.dry_run),
        "output": None if args.dry_run else str(args.output),
    }


def _run_benchmark(args: argparse.Namespace) -> dict[str, object]:
    truth = _load_observations(args.truth_json)
    skan = _load_observations(args.skan_json)
    nmap = parse_nmap_xml(args.nmap_xml.read_text(encoding="utf-8"))
    metadata, metadata_complete = _load_benchmark_metadata(args.metadata_json)
    metrics = benchmark(truth, skan, nmap)
    return {
        "metrics": metrics,
        "metadata": metadata,
        "metadata_complete": metadata_complete,
        "better_than_nmap_gate": better_than_nmap_gate(metrics, metadata_complete=metadata_complete),
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command in {"verify", "stats"}:
            summary: dict[str, object] = validate_root(args.root)
        elif args.command == "import":
            summary = _run_import(args)
        elif args.command == "refresh-from-snapshot":
            summary = _run_refresh(args)
        elif args.command == "benchmark":
            summary = _run_benchmark(args)
        else:
            raise ValueError(f"unsupported command: {args.command}")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"corpus {args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
