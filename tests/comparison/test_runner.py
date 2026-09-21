from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.comparison.cli import main as comparison_main
from tools.comparison.manifest import load_manifest
from tools.comparison.model import RunStatus, ScannerRun
from tools.comparison.parsers import MAX_RESULT_BYTES, parse_skan_json
from tools.comparison.runner import run_command, run_suite


FIXTURES = Path(__file__).with_name("fixtures")


class ComparisonRunnerTests(unittest.TestCase):
    def test_runs_a_parser_without_a_shell(self) -> None:
        fixture = str(FIXTURES / "skan-valid.json")
        program = "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
        run = run_command(
            "skan",
            [sys.executable, "-c", program, fixture],
            5.0,
            parse_skan_json,
        )
        self.assertEqual(run.status, RunStatus.COMPLETE)
        self.assertEqual(len(run.observations), 2)

    def test_uses_live_bounded_pipe_drains_and_rejects_excess_output(self) -> None:
        fixture = str(FIXTURES / "skan-valid.json")
        program = "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
        with patch("tools.comparison.runner.subprocess.run", side_effect=AssertionError("unbounded runner")):
            completed = run_command(
                "skan",
                [sys.executable, "-c", program, fixture],
                5.0,
                parse_skan_json,
            )
        self.assertEqual(completed.status, RunStatus.COMPLETE)

        excessive_program = (
            "import os;chunk=b'x'*65536;"
            f"[os.write(1,chunk) for _ in range({MAX_RESULT_BYTES // 65536 + 2})]"
        )
        excessive = run_command(
            "skan",
            [sys.executable, "-c", excessive_program],
            5.0,
            parse_skan_json,
        )
        self.assertEqual(excessive.status, RunStatus.INVALID)
        self.assertIn("stdout exceeds", excessive.diagnostic)

    def test_reports_missing_timeout_error_and_bounded_diagnostics(self) -> None:
        missing = run_command("skan", ["/definitely/missing/skan"], 1.0, parse_skan_json)
        self.assertEqual(missing.status, RunStatus.UNAVAILABLE)

        timeout = run_command(
            "skan",
            [sys.executable, "-c", "import time; time.sleep(2)"],
            0.05,
            parse_skan_json,
        )
        self.assertEqual(timeout.status, RunStatus.TIMEOUT)

        error = run_command(
            "skan",
            [sys.executable, "-c", "import sys; sys.stderr.write('x'*10000); raise SystemExit(7)"],
            2.0,
            parse_skan_json,
        )
        self.assertEqual(error.status, RunStatus.ERROR)
        self.assertLessEqual(len(error.diagnostic), 4120)
        self.assertIn("truncated", error.diagnostic)

    def test_suite_executes_skan_then_nmap_for_each_scenario(self) -> None:
        document = {
            "schema_version": 1,
            "suite_id": "order-v1",
            "scenarios": [
                {
                    "id": "first",
                    "target": "127.0.0.1",
                    "protocol": "tcp",
                    "timeout_seconds": 1,
                    "authorization": "operator-controlled-lab",
                    "expectations": [{"port": 80, "state": "open"}],
                },
                {
                    "id": "second",
                    "target": "127.0.0.2",
                    "protocol": "tcp",
                    "timeout_seconds": 1,
                    "authorization": "operator-controlled-lab",
                    "expectations": [{"port": 81, "state": "closed"}],
                },
            ],
        }
        with tempfile.TemporaryDirectory(prefix="skan-comparison-runner-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            manifest = load_manifest(path)
        completed = ScannerRun("fixture", "1", RunStatus.COMPLETE, 1.0, ())
        calls: list[str] = []

        def fake(scanner, argv, timeout, parser):
            del argv, timeout, parser
            calls.append(scanner)
            return completed

        with patch("tools.comparison.runner.run_command", side_effect=fake):
            results = run_suite(manifest, "skan", "nmap")
        self.assertEqual(calls, ["skan", "nmap", "skan", "nmap"])
        self.assertEqual(set(results["skan"]), {"first", "second"})
        self.assertEqual(set(results["nmap"]), {"first", "second"})

    def test_offline_cli_scores_captured_outputs_without_scanning(self) -> None:
        document = {
            "schema_version": 1,
            "suite_id": "captured-v1",
            "scenarios": [
                {
                    "id": "web",
                    "target": "127.0.0.1",
                    "protocol": "tcp",
                    "timeout_seconds": 30,
                    "authorization": "operator-controlled-lab",
                    "expectations": [
                        {
                            "port": 8080,
                            "state": "open",
                            "service": "http",
                            "product": "exampled",
                            "version": "1.2.3",
                        },
                        {"port": 8081, "state": "closed"},
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory(prefix="skan-comparison-cli-") as directory:
            work = Path(directory)
            manifest = work / "manifest.json"
            json_report = work / "scorecard.json"
            markdown_report = work / "scorecard.md"
            manifest.write_text(json.dumps(document), encoding="utf-8")
            result = comparison_main(
                [
                    "score",
                    "--manifest",
                    str(manifest),
                    "--skan-json",
                    str(FIXTURES / "skan-valid.json"),
                    "--nmap-xml",
                    str(FIXTURES / "nmap-valid.xml"),
                    "--json",
                    str(json_report),
                    "--markdown",
                    str(markdown_report),
                ]
            )
            self.assertEqual(result, 0)
            self.assertFalse(json.loads(json_report.read_text(encoding="utf-8"))["superiority"]["claim_allowed"])
            self.assertIn("NOT ELIGIBLE", markdown_report.read_text(encoding="utf-8"))

    def test_cli_verifies_hash_bound_multi_scenario_baseline_without_scanning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-baseline-cli-") as directory:
            work = Path(directory)
            json_report = work / "scorecard.json"
            markdown_report = work / "scorecard.md"
            with patch(
                "tools.comparison.cli.run_suite",
                side_effect=AssertionError("offline baseline verification launched scanners"),
            ):
                result = comparison_main(
                    [
                        "verify-baseline",
                        "--bundle",
                        str(FIXTURES / "baseline-v1" / "baseline.json"),
                        "--json",
                        str(json_report),
                        "--markdown",
                        str(markdown_report),
                    ]
                )

            self.assertEqual(result, 0)
            report = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(report["environment"]["baseline_id"], "synthetic-contract-v1")
            self.assertEqual(report["environment"]["execution"], "offline-versioned-baseline")
            self.assertEqual(report["environment"]["benchmark_conditions"], "clean-lan,latency-20ms")
            self.assertEqual(
                report["benchmark_scenarios"],
                [
                    {
                        "condition": "clean-lan",
                        "profile": "synthetic-contract",
                        "scenario_id": "clean-01",
                    },
                    {
                        "condition": "latency-20ms",
                        "profile": "synthetic-contract",
                        "scenario_id": "latency-01",
                    },
                ],
            )
            self.assertEqual(len(report["scanners"]["skan"]["runs"]), 2)
            self.assertEqual(len(report["scanners"]["nmap"]["runs"]), 2)
            self.assertFalse(report["superiority"]["claim_allowed"])
            self.assertIn("NOT ELIGIBLE", markdown_report.read_text(encoding="utf-8"))

    def test_baseline_cli_reports_symlink_loop_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-loop-") as directory:
            work = Path(directory)
            (work / "loop.json").symlink_to("loop.json")
            artifact = {"path": "loop.json", "sha256": "0" * 64}
            descriptor = {
                "schema_version": 1,
                "baseline_id": "loop-v1",
                "manifest": artifact,
                "environment": {"lab": "synthetic-fixture"},
                "captures": [
                    {
                        "scenario_id": "loop-01",
                        "profile": "synthetic-contract",
                        "condition": "clean-lan",
                        "skan": artifact,
                        "nmap": artifact,
                    }
                ],
            }
            bundle = work / "baseline.json"
            bundle.write_text(json.dumps(descriptor), encoding="utf-8")
            diagnostic = io.StringIO()
            with redirect_stderr(diagnostic):
                result = comparison_main(
                    [
                        "verify-baseline",
                        "--bundle",
                        str(bundle),
                        "--json",
                        str(work / "scorecard.json"),
                        "--markdown",
                        str(work / "scorecard.md"),
                    ]
                )

        self.assertEqual(result, 2)
        self.assertIn("Too many levels", diagnostic.getvalue())
        self.assertNotIn("Traceback", diagnostic.getvalue())


if __name__ == "__main__":
    unittest.main()
