from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAX_DATABASE_BYTES = 1 << 20


class UDPLoaderBoundsTest(unittest.TestCase):
    def test_udp_database_loader_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            binary = tmp / "udp_loader_bounds_probe"
            oversized = tmp / "oversized.db"
            valid = tmp / "valid.db"

            oversized.write_bytes(
                b"probe DEFAULT 0 generic 512 00\n#"
                + b"x" * MAX_DATABASE_BYTES
            )
            self.assertGreater(oversized.stat().st_size, MAX_DATABASE_BYTES)
            valid.write_text("probe DEFAULT 0 generic 512 00\n", encoding="ascii")

            compile_result = subprocess.run(
                [
                    "g++",
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Wshadow",
                    "-Wconversion",
                    "-Wformat=2",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-Iinclude",
                    "tests/corpus/udp_loader_bounds_probe.cpp",
                    "src/portscan/udp_scan.cpp",
                    "-Wl,--gc-sections",
                    "-o",
                    str(binary),
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

            run_result = subprocess.run(
                [str(binary), str(oversized), str(valid)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                run_result.stdout + run_result.stderr,
            )

            source = (ROOT / "src/portscan/udp_scan.cpp").read_text(encoding="utf-8")
            loader = source[source.index("UDPProbeDatabase UDPProbeDatabase::load_file") :]
            loader = loader[: loader.index("const UDPProbeDefinition *UDPProbeDatabase::for_port")]
            self.assertNotIn("rdbuf()", loader)
            self.assertIn("kMaximumDatabaseBytes", loader)


if __name__ == "__main__":
    unittest.main()
