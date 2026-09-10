from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.corpus.udp_pipeline import build_udp_artifacts


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform.startswith("linux"), "real UDP loader gate currently runs on Linux")
class UDPRealLoaderGateTests(unittest.TestCase):
    def test_generated_runtime_db_is_semantically_equal_in_production_cpp_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            canonical = work / "udp.jsonl"
            generated = work / "udp-probes.db"
            count = build_udp_artifacts(
                legacy_path=ROOT / "data" / "udp-probes.db",
                manifest_path=ROOT / "corpus" / "sources" / "sources.json",
                canonical_path=canonical,
                runtime_path=generated,
            )
            self.assertEqual(count, 21)

            executable = work / "udp_loader_probe"
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
                    f"-I{ROOT / 'include'}",
                    str(ROOT / "tests" / "corpus" / "udp_loader_probe.cpp"),
                    str(ROOT / "src" / "portscan" / "udp_scan.cpp"),
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
                    "failed to compile real UDP loader equivalence probe:\n"
                    + compile_result.stdout
                    + compile_result.stderr
                )

            verification = subprocess.run(
                [
                    str(executable),
                    str(ROOT / "data" / "udp-probes.db"),
                    str(generated),
                ],
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
