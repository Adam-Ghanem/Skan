from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.corpus.os_pipeline import build_os_artifacts


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform.startswith("linux"), "real OS loader gate currently runs on Linux")
class OSRealLoaderGateTests(unittest.TestCase):
    def test_generated_runtime_dbs_are_semantically_equal_in_production_cpp_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            canonical = work / "os.jsonl"
            generated_ipv4 = work / "os-fingerprints.db"
            generated_ipv6 = work / "os-fingerprints-v6.db"
            count = build_os_artifacts(
                legacy_ipv4_path=ROOT / "data" / "os-fingerprints.db",
                legacy_ipv6_path=ROOT / "data" / "os-fingerprints-v6.db",
                manifest_path=ROOT / "corpus" / "sources" / "sources.json",
                canonical_path=canonical,
                runtime_ipv4_path=generated_ipv4,
                runtime_ipv6_path=generated_ipv6,
            )
            self.assertGreaterEqual(count, 40)
            self.assertLessEqual(count, 256)

            executable = work / "os_loader_probe"
            compiler = os.environ.get("CXX", "g++")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-ffunction-sections",
                    "-fdata-sections",
                    '-DSKAN_DATA_DIR="/usr/share/skan"',
                    f"-I{ROOT / 'include'}",
                    str(ROOT / "tests" / "corpus" / "os_loader_probe.cpp"),
                    str(ROOT / "src" / "db" / "os_db.cpp"),
                    str(ROOT / "src" / "core" / "runtime_paths.cpp"),
                    "-Wl,--gc-sections",
                    "-o",
                    str(executable),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if compile_result.returncode != 0:
                self.fail(
                    "failed to compile real OS loader equivalence probe:\n"
                    + compile_result.stdout
                    + compile_result.stderr
                )

            cases = (
                ("ipv4", ROOT / "data" / "os-fingerprints.db", generated_ipv4),
                ("ipv6", ROOT / "data" / "os-fingerprints-v6.db", generated_ipv6),
            )
            for family, legacy, generated in cases:
                with self.subTest(family=family):
                    verification = subprocess.run(
                        [str(executable), family, str(legacy), str(generated)],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        verification.returncode,
                        0,
                        msg=verification.stdout + verification.stderr,
                    )


if __name__ == "__main__":
    unittest.main()
