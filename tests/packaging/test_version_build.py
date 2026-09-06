#!/usr/bin/env python3
"""Prove that VERSION changes propagate through the real incremental Make rules."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class VersionBuildTests(unittest.TestCase):
    def check_version_rebuild(self, source_name, object_name):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as directory:
            project = Path(directory)
            shutil.copyfile(ROOT / "Makefile", project / "Makefile")
            version = project / "VERSION"
            version.write_text("1.2.3\n")
            source = project / source_name
            source.parent.mkdir(parents=True)
            source.write_text(
                '#include <stdio.h>\n'
                'int main(void) { printf("%s|%u|%u|%u\\n", SKAN_VERSION_VALUE,\n'
                'SKAN_VERSION_MAJOR_VALUE, SKAN_VERSION_MINOR_VALUE,\n'
                'SKAN_VERSION_PATCH_VALUE); return 0; }\n'
            )

            def build_and_run():
                build = subprocess.run(
                    ["make", object_name], cwd=project,
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                subprocess.run(
                    ["g++", object_name, "-o", "version-probe"], cwd=project,
                    capture_output=True, text=True, check=True,
                )
                return subprocess.check_output(
                    [str(project / "version-probe")], text=True,
                )

            self.assertEqual(build_and_run(), "1.2.3|1|2|3\n")
            # Ensure deterministic dependency ordering even on coarse clocks.
            object_file = project / object_name
            previous = object_file.stat().st_mtime_ns - 2_000_000_000
            os.utime(source, ns=(previous - 2_000_000_000, previous - 2_000_000_000))
            os.utime(object_file, ns=(previous, previous))
            version.write_text("1.2.4\n")
            self.assertEqual(build_and_run(), "1.2.4|1|2|4\n")

    def test_version_change_rebuilds_existing_objects(self):
        for source, target in (
            ("src/core/types.cpp", "build/core/types.o"),
            ("src/c_api/status.c", "build/c_api/status.o"),
            ("tests/unit/core/test_constants.cpp", "build/tests/unit/core/test_constants.o"),
            ("benchmarks/offline.cpp", "build/benchmarks/offline.o"),
        ):
            with self.subTest(source=source):
                self.check_version_rebuild(source, target)


if __name__ == "__main__":
    unittest.main()
