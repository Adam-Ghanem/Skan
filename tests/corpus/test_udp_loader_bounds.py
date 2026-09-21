from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAXIMUM_DATABASE_BYTES = 1 << 20
VALID_DATABASE = b"probe DEFAULT 0 generic 512 00\n"


@unittest.skipUnless(sys.platform.startswith("linux"), "real UDP loader gate currently runs on Linux")
class UDPDatabaseBoundsTests(unittest.TestCase):
    def test_direct_and_file_inputs_share_a_strict_one_mebibyte_limit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="skan-udp-bounds-") as directory:
            work = Path(directory)
            oversized = work / "oversized.db"
            valid = work / "valid.db"
            missing = work / "missing.db"

            oversized_prefix = VALID_DATABASE + b"#"
            oversized.write_bytes(
                oversized_prefix
                + b"x" * (MAXIMUM_DATABASE_BYTES + 1 - len(oversized_prefix))
            )
            valid.write_bytes(VALID_DATABASE)

            executable = work / "udp_loader_bounds_probe"
            compiler = os.environ.get("CXX", "g++")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Wshadow",
                    "-Wconversion",
                    "-Wformat=2",
                    "-ffunction-sections",
                    "-fdata-sections",
                    f"-I{ROOT / 'include'}",
                    str(ROOT / "tests" / "corpus" / "udp_loader_bounds_probe.cpp"),
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
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )

            verification = subprocess.run(
                [str(executable), str(oversized), str(valid), str(missing)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                verification.returncode,
                0,
                verification.stdout + verification.stderr,
            )

            source = (ROOT / "src/portscan/udp_scan.cpp").read_text(encoding="utf-8")
            loader = source[source.index("UDPProbeDatabase UDPProbeDatabase::load_file") :]
            loader = loader[: loader.index("const UDPProbeDefinition *UDPProbeDatabase::for_port")]
            self.assertNotIn("rdbuf()", loader)
            self.assertIn("kMaximumDatabaseBytes", loader)


if __name__ == "__main__":
    unittest.main()
