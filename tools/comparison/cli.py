from __future__ import annotations

import argparse
from pathlib import Path
import platform
import sys

from .baseline import BaselineError, load_baseline
from .manifest import ManifestError, load_manifest
from .model import ScannerRun
from .parsers import MAX_RESULT_BYTES, ResultParseError, parse_nmap_xml, parse_skan_json
from .report import write_reports
from .runner import run_suite
from .scoring import build_scorecard


def _read_result(path: str) -> bytes:
    source = Path(path)
    try:
        with source.open("rb") as stream:
            data = stream.read(MAX_RESULT_BYTES + 1)
    except OSError as error:
        raise ResultParseError(f"cannot read scanner result: {error}") from error
    if len(data) > MAX_RESULT_BYTES:
        raise ResultParseError("scanner result exceeds the size limit")
    return data


def _environment(mode: str) -> dict[str, str]:
    return {
        "execution": mode,
        "machine": platform.machine(),
        "platform": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare scanners against authorized lab ground truth")
    subparsers = parser.add_subparsers(dest="command", required=True)

    score = subparsers.add_parser("score", help="score one captured scenario without network access")
    score.add_argument("--manifest", required=True)
    score.add_argument("--skan-json", required=True)
    score.add_argument("--nmap-xml", required=True)
    score.add_argument("--json", required=True, dest="json_output")
    score.add_argument("--markdown", required=True, dest="markdown_output")

    verify = subparsers.add_parser(
        "verify-baseline", help="verify and score a hash-bound multi-scenario bundle offline"
    )
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--json", required=True, dest="json_output")
    verify.add_argument("--markdown", required=True, dest="markdown_output")

    run = subparsers.add_parser("run", help="run sequential scans in an operator-controlled lab")
    run.add_argument("--manifest", required=True)
    run.add_argument("--skan-bin", default="bin/skan")
    run.add_argument("--nmap-bin", default="nmap")
    run.add_argument("--json", required=True, dest="json_output")
    run.add_argument("--markdown", required=True, dest="markdown_output")
    return parser


def _captured_runs(manifest, skan_path: str, nmap_path: str) -> dict[str, dict[str, ScannerRun]]:
    if len(manifest.scenarios) != 1:
        raise ManifestError("offline score mode requires exactly one scenario")
    identifier = manifest.scenarios[0].identifier
    return {
        "skan": {identifier: parse_skan_json(_read_result(skan_path))},
        "nmap": {identifier: parse_nmap_xml(_read_result(nmap_path))},
    }


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        benchmark_scenarios = ()
        if arguments.command == "verify-baseline":
            baseline = load_baseline(arguments.bundle)
            manifest = baseline.manifest
            runs = baseline.scanner_runs
            environment = dict(baseline.environment)
            benchmark_scenarios = baseline.benchmark_scenarios
        else:
            manifest = load_manifest(arguments.manifest)
        if arguments.command == "score":
            runs = _captured_runs(manifest, arguments.skan_json, arguments.nmap_xml)
            environment = _environment("offline-captured-results")
        elif arguments.command == "run":
            runs = run_suite(manifest, arguments.skan_bin, arguments.nmap_bin)
            environment = _environment("operator-controlled-lab")
        scorecard = build_scorecard(
            manifest,
            runs,
            environment,
            quality_gates_passed=False,
            benchmark_scenarios=benchmark_scenarios,
        )
        write_reports(scorecard, arguments.json_output, arguments.markdown_output)
    except (BaselineError, ManifestError, ResultParseError, OSError, ValueError) as error:
        print(f"comparison error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
