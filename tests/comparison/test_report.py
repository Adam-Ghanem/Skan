from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.comparison.model import (
    ComparisonManifest,
    Endpoint,
    Expectation,
    Observation,
    RunStatus,
    ScannerRun,
    Scenario,
)
from tools.comparison.report import render_json, render_markdown, write_reports
from tools.comparison.scoring import build_scorecard


class ComparisonReportTests(unittest.TestCase):
    def scorecard(self):
        endpoint = Endpoint("127.0.0.1", "tcp", 8080)
        manifest = ComparisonManifest(
            1,
            "report-v1",
            (
                Scenario(
                    "web",
                    endpoint.target,
                    endpoint.protocol,
                    30.0,
                    "operator-controlled-lab",
                    (Expectation(endpoint, "open", "http", "exampled", "1.2.3"),),
                ),
            ),
        )
        skan = ScannerRun(
            "Skan",
            "0.1.1",
            RunStatus.COMPLETE,
            0.5,
            (Observation(endpoint, "open", service="http", product="exampled", version="1.2.3"),),
        )
        nmap = ScannerRun(
            "Nmap",
            "7.95",
            RunStatus.COMPLETE,
            1.0,
            (Observation(endpoint, "open", service="http", product="exampled", version="1.2.3"),),
        )
        return build_scorecard(
            manifest,
            {"skan": {"web": skan}, "nmap": {"web": nmap}},
            {"kernel": "test", "profile": "loopback"},
            quality_gates_passed=False,
        )

    def test_json_and_markdown_are_stable_and_include_a_manifest_digest(self) -> None:
        scorecard = self.scorecard()
        first = render_json(scorecard)
        self.assertEqual(first, render_json(scorecard))
        self.assertEqual(
            hashlib.sha256(first.encode("utf-8")).hexdigest(),
            "879007818599eedbf7e7127af7047bffe341a18bac3b9564a2b70ddc02056d14",
        )
        parsed = json.loads(first)
        self.assertRegex(parsed["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(parsed["superiority"]["claim_allowed"])
        self.assertEqual(parsed["environment"]["kernel"], "test")
        self.assertEqual(parsed["scanners"]["skan"]["elapsed_seconds"]["samples"], [0.5])

        markdown = render_markdown(scorecard)
        self.assertEqual(markdown, render_markdown(scorecard))
        self.assertEqual(
            hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
            "3952098052e22df41430fa8f5184c74a1effb65ae8f8079dc86dde20dbe44e7c",
        )
        self.assertIn("NOT ELIGIBLE", markdown)
        self.assertIn("Quality gates", markdown)
        self.assertIn(scorecard.manifest_sha256, markdown)

    def test_markdown_environment_values_use_unbreakable_code_spans(self) -> None:
        scorecard = replace(self.scorecard(), environment=(("lab", "edge`node"),))
        markdown = render_markdown(scorecard)
        self.assertIn("- lab: ``edge`node``", markdown)

    def test_atomic_report_write_replaces_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-report-") as directory:
            json_path = Path(directory) / "scorecard.json"
            markdown_path = Path(directory) / "scorecard.md"
            json_path.write_text("old", encoding="utf-8")
            markdown_path.write_text("old", encoding="utf-8")
            write_reports(self.scorecard(), json_path, markdown_path)
            self.assertTrue(json_path.read_text(encoding="utf-8").endswith("\n"))
            self.assertTrue(markdown_path.read_text(encoding="utf-8").endswith("\n"))
            self.assertFalse(any(Path(directory).glob("*.tmp")))

    def test_report_write_rejects_same_target_and_rolls_back_second_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-report-") as directory:
            json_path = Path(directory) / "scorecard.json"
            markdown_path = Path(directory) / "scorecard.md"
            with self.assertRaisesRegex(ValueError, "distinct"):
                write_reports(self.scorecard(), json_path, json_path)

            json_path.write_text("old-json", encoding="utf-8")
            markdown_path.write_text("old-markdown", encoding="utf-8")
            real_replace = __import__("os").replace
            failed = False

            def fail_markdown_once(source, destination):
                nonlocal failed
                if Path(destination) == markdown_path and not failed:
                    failed = True
                    raise OSError("injected second-report failure")
                return real_replace(source, destination)

            with patch("tools.comparison.report.os.replace", side_effect=fail_markdown_once):
                with self.assertRaisesRegex(OSError, "injected"):
                    write_reports(self.scorecard(), json_path, markdown_path)
            self.assertEqual(json_path.read_text(encoding="utf-8"), "old-json")
            self.assertEqual(markdown_path.read_text(encoding="utf-8"), "old-markdown")

    def test_failed_restore_preserves_backup_and_committed_cleanup_does_not_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-comparison-report-") as directory:
            work = Path(directory)
            json_path = work / "scorecard.json"
            markdown_path = work / "scorecard.md"
            json_path.write_text("old-json", encoding="utf-8")
            markdown_path.write_text("old-markdown", encoding="utf-8")
            real_replace = __import__("os").replace
            install_failed = False

            def fail_install_and_json_restore(source, destination):
                nonlocal install_failed
                source_path = Path(source)
                destination_path = Path(destination)
                if destination_path == markdown_path and source_path.suffix == ".tmp" and not install_failed:
                    install_failed = True
                    raise OSError("injected install failure")
                if destination_path == json_path and source_path.suffix == ".backup":
                    raise OSError("injected restore failure")
                return real_replace(source, destination)

            with patch("tools.comparison.report.os.replace", side_effect=fail_install_and_json_restore):
                with self.assertRaisesRegex(OSError, "injected install"):
                    write_reports(self.scorecard(), json_path, markdown_path)
            backups = list(work.glob(".scorecard.json.*.backup"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), "old-json")
            self.assertEqual(markdown_path.read_text(encoding="utf-8"), "old-markdown")

        with tempfile.TemporaryDirectory(prefix="skan-comparison-report-") as directory:
            work = Path(directory)
            json_path = work / "scorecard.json"
            markdown_path = work / "scorecard.md"
            json_path.write_text("old-json", encoding="utf-8")
            markdown_path.write_text("old-markdown", encoding="utf-8")
            real_unlink = Path.unlink

            def fail_backup_cleanup(path, *args, **kwargs):
                if path.suffix == ".backup" and path.exists() and path.stat().st_size > 0:
                    raise OSError("injected cleanup failure")
                return real_unlink(path, *args, **kwargs)

            with patch("tools.comparison.report.Path.unlink", new=fail_backup_cleanup):
                write_reports(self.scorecard(), json_path, markdown_path)
            self.assertTrue(json_path.read_text(encoding="utf-8").startswith("{"))
            self.assertTrue(markdown_path.read_text(encoding="utf-8").startswith("# Scanner Comparison"))


if __name__ == "__main__":
    unittest.main()
