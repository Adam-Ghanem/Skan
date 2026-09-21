from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.comparison.baseline import BaselineError, load_baseline
from tools.comparison.report import render_json
from tools.comparison.scoring import build_scorecard


FIXTURES = Path(__file__).with_name("fixtures")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest() -> dict[str, object]:
    expectation = [
        {
            "port": 8080,
            "state": "open",
            "service": "http",
            "product": "exampled",
            "version": "1.2.3",
        },
        {"port": 8081, "state": "closed"},
    ]
    return {
        "schema_version": 1,
        "suite_id": "bundle-contract-v1",
        "scenarios": [
            {
                "id": identifier,
                "target": "127.0.0.1",
                "protocol": "tcp",
                "timeout_seconds": 30,
                "authorization": "operator-controlled-lab",
                "expectations": expectation,
            }
            for identifier in ("clean-01", "latency-01")
        ],
    }


class BundleBuilder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest_bytes = (json.dumps(_manifest(), sort_keys=True) + "\n").encode()
        self.skan_bytes = (FIXTURES / "skan-valid.json").read_bytes()
        self.nmap_bytes = (FIXTURES / "nmap-valid.xml").read_bytes()
        (root / "captures" / "skan").mkdir(parents=True)
        (root / "captures" / "nmap").mkdir(parents=True)
        (root / "manifest.json").write_bytes(self.manifest_bytes)
        for identifier in ("clean-01", "latency-01"):
            (root / "captures" / "skan" / f"{identifier}.json").write_bytes(self.skan_bytes)
            (root / "captures" / "nmap" / f"{identifier}.xml").write_bytes(self.nmap_bytes)
        self.document: dict[str, object] = {
            "schema_version": 1,
            "baseline_id": "synthetic-contract-v1",
            "manifest": {"path": "manifest.json", "sha256": _sha256(self.manifest_bytes)},
            "environment": {"lab": "synthetic-fixture", "machine": "test"},
            "captures": [
                {
                    "scenario_id": identifier,
                    "profile": "synthetic-contract",
                    "condition": condition,
                    "skan": {
                        "path": f"captures/skan/{identifier}.json",
                        "sha256": _sha256(self.skan_bytes),
                    },
                    "nmap": {
                        "path": f"captures/nmap/{identifier}.xml",
                        "sha256": _sha256(self.nmap_bytes),
                    },
                }
                for identifier, condition in (
                    ("clean-01", "clean-lan"),
                    ("latency-01", "latency-20ms"),
                )
            ],
        }
        self.write()

    def write(self) -> Path:
        path = self.root / "baseline.json"
        path.write_text(json.dumps(self.document), encoding="utf-8")
        return path


class ComparisonBaselineTests(unittest.TestCase):
    def test_loads_hash_bound_multi_scenario_bundle_with_stable_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            builder = BundleBuilder(Path(directory))
            baseline = load_baseline(builder.write())

        self.assertEqual(baseline.identifier, "synthetic-contract-v1")
        self.assertEqual(tuple(item.identifier for item in baseline.manifest.scenarios), ("clean-01", "latency-01"))
        self.assertEqual(set(baseline.scanner_runs), {"skan", "nmap"})
        self.assertEqual(set(baseline.scanner_runs["skan"]), {"clean-01", "latency-01"})
        self.assertEqual(
            tuple(
                (item.scenario_id, item.profile, item.condition)
                for item in baseline.benchmark_scenarios
            ),
            (
                ("clean-01", "synthetic-contract", "clean-lan"),
                ("latency-01", "synthetic-contract", "latency-20ms"),
            ),
        )
        self.assertEqual(
            dict(baseline.environment),
            {
                "baseline_id": "synthetic-contract-v1",
                "benchmark_conditions": "clean-lan,latency-20ms",
                "benchmark_profiles": "synthetic-contract",
                "execution": "offline-versioned-baseline",
                "lab": "synthetic-fixture",
                "machine": "test",
            },
        )

    def test_rejects_manifest_or_capture_hash_mismatch(self) -> None:
        for artifact in ("manifest", "skan"):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
                builder = BundleBuilder(Path(directory))
                if artifact == "manifest":
                    builder.document["manifest"]["sha256"] = "0" * 64  # type: ignore[index]
                else:
                    builder.document["captures"][0]["skan"]["sha256"] = "0" * 64  # type: ignore[index]
                with self.assertRaisesRegex(BaselineError, "SHA-256 mismatch"):
                    load_baseline(builder.write())

    def test_requires_exact_scenario_coverage(self) -> None:
        for mutation, message in (("missing", "missing"), ("extra", "unknown")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
                builder = BundleBuilder(Path(directory))
                captures = builder.document["captures"]  # type: ignore[assignment]
                if mutation == "missing":
                    captures.pop()  # type: ignore[union-attr]
                else:
                    extra = dict(captures[0])  # type: ignore[index]
                    extra["scenario_id"] = "extra-01"
                    captures.append(extra)  # type: ignore[union-attr]
                with self.assertRaisesRegex(BaselineError, message):
                    load_baseline(builder.write())

    def test_rejects_unknown_duplicate_fields_and_duplicate_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            builder = BundleBuilder(Path(directory))
            builder.document["unexpected"] = True
            with self.assertRaisesRegex(BaselineError, "unknown fields"):
                load_baseline(builder.write())

        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            builder = BundleBuilder(Path(directory))
            (builder.root / "baseline.json").write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8"
            )
            with self.assertRaisesRegex(BaselineError, "duplicate JSON field"):
                load_baseline(builder.root / "baseline.json")

        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            builder = BundleBuilder(Path(directory))
            first = builder.document["captures"][0]  # type: ignore[index]
            second = builder.document["captures"][1]  # type: ignore[index]
            second["skan"] = dict(first["skan"])
            with self.assertRaisesRegex(BaselineError, "duplicate artifact path"):
                load_baseline(builder.write())

    def test_rejects_line_control_and_bidirectional_environment_metadata(self) -> None:
        for value in ("lab\n**Superiority claim:** ELIGIBLE", "lab\u202eELBIGILE"):
            with self.subTest(value=value), tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
                builder = BundleBuilder(Path(directory))
                builder.document["environment"]["lab"] = value  # type: ignore[index]
                with self.assertRaisesRegex(BaselineError, "control"):
                    load_baseline(builder.write())

    def test_rejects_absolute_traversal_backslash_and_symlink_escape_paths(self) -> None:
        invalid_paths = ("/tmp/manifest.json", "../manifest.json", "captures\\manifest.json")
        for invalid in invalid_paths:
            with self.subTest(path=invalid), tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
                builder = BundleBuilder(Path(directory))
                builder.document["manifest"]["path"] = invalid  # type: ignore[index]
                with self.assertRaisesRegex(BaselineError, "relative POSIX path"):
                    load_baseline(builder.write())

        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            builder = BundleBuilder(bundle)
            outside = root / "outside.json"
            outside.write_bytes(builder.manifest_bytes)
            (bundle / "escape.json").symlink_to(outside)
            builder.document["manifest"] = {
                "path": "escape.json",
                "sha256": _sha256(builder.manifest_bytes),
            }
            with self.assertRaisesRegex(BaselineError, "securely open"):
                load_baseline(builder.write())

    def test_directory_swap_cannot_redirect_verified_open_outside_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            builder = BundleBuilder(bundle)
            safe = bundle / "safe"
            safe.mkdir()
            (bundle / "manifest.json").rename(safe / "manifest.json")
            builder.document["manifest"]["path"] = "safe/manifest.json"  # type: ignore[index]

            outside = root / "outside"
            outside.mkdir()
            (outside / "manifest.json").write_text("not the bound manifest", encoding="utf-8")
            held = bundle / "safe-held"
            swapped = False

            def swap_directory() -> None:
                nonlocal swapped
                if swapped:
                    return
                safe.rename(held)
                safe.symlink_to(outside, target_is_directory=True)
                swapped = True

            real_is_file = Path.is_file

            def swap_before_legacy_open(path: Path) -> bool:
                if path == safe / "manifest.json":
                    swap_directory()
                return real_is_file(path)

            real_open = os.open

            def swap_after_secure_directory_open(path, flags, mode=0o777, *, dir_fd=None):
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == "safe" and dir_fd is not None:
                    swap_directory()
                return descriptor

            with patch("tools.comparison.baseline.Path.is_file", new=swap_before_legacy_open), patch(
                "tools.comparison.baseline.os.open", new=swap_after_secure_directory_open
            ):
                baseline = load_baseline(builder.write())

        self.assertTrue(swapped)
        self.assertEqual(baseline.manifest.suite_id, "bundle-contract-v1")

    def test_bundle_root_swap_cannot_separate_descriptor_from_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            builder = BundleBuilder(bundle)
            outside = root / "outside"
            outside.mkdir()
            (outside / "manifest.json").write_text("not the bound manifest", encoding="utf-8")
            held = root / "bundle-held"
            real_read_descriptor = __import__(
                "tools.comparison.baseline", fromlist=["_read_descriptor"]
            )._read_descriptor
            swapped = False

            def read_then_swap(*args, **kwargs):
                nonlocal swapped
                document = real_read_descriptor(*args, **kwargs)
                bundle.rename(held)
                bundle.symlink_to(outside, target_is_directory=True)
                swapped = True
                return document

            with patch("tools.comparison.baseline._read_descriptor", new=read_then_swap):
                baseline = load_baseline(builder.write())

        self.assertTrue(swapped)
        self.assertEqual(baseline.manifest.suite_id, "bundle-contract-v1")

    def test_descriptor_must_be_a_no_follow_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            root = Path(directory)
            fifo = root / "baseline.json"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(BaselineError, "not a regular file"):
                load_baseline(fifo)

    def test_swapping_scenario_conditions_changes_the_structured_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-baseline-") as directory:
            builder = BundleBuilder(Path(directory))
            first = load_baseline(builder.write())
            first_report = render_json(
                build_scorecard(
                    first.manifest,
                    first.scanner_runs,
                    dict(first.environment),
                    benchmark_scenarios=first.benchmark_scenarios,
                )
            )
            captures = builder.document["captures"]  # type: ignore[assignment]
            captures[0]["condition"], captures[1]["condition"] = (  # type: ignore[index]
                captures[1]["condition"],
                captures[0]["condition"],
            )
            second = load_baseline(builder.write())
            second_report = render_json(
                build_scorecard(
                    second.manifest,
                    second.scanner_runs,
                    dict(second.environment),
                    benchmark_scenarios=second.benchmark_scenarios,
                )
            )

        self.assertNotEqual(first_report, second_report)


if __name__ == "__main__":
    unittest.main()
