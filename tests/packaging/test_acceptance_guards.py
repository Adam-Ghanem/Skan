#!/usr/bin/env python3
"""Exercise packaging guardrails that keep Debian builds reproducible."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PurgePathGuardTests(unittest.TestCase):
    def check_guard(self, remove: bool) -> subprocess.CompletedProcess[str]:
        harness = (ROOT / "tests/packaging/deb_acceptance.sh").read_text()
        # Run the actual post-purge PATH check, without installing/removing a
        # system package. The fixture represents the executable apt removes.
        guard = harness.split("apt-get purge -y skan >/dev/null\n", 1)[1]
        guard = guard.split("if dpkg-query", 1)[0]
        temporary_root = ROOT / "build"
        temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
            executable = Path(directory) / "skan"
            shutil.copyfile("/bin/true", executable)
            executable.chmod(0o755)
            setup = 'export PATH="$1"\nskan\n'
            if remove:
                setup += '/bin/rm -- "$1/skan"\n'
            return subprocess.run(
                ["bash", "-ec", setup + guard, "guard-test", directory],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_removed_executable_is_not_mistaken_for_cached_command(self):
        result = self.check_guard(remove=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_executable_still_on_path_fails_acceptance(self):
        result = self.check_guard(remove=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("skan remains on PATH after purge", result.stderr)


class DebianBuildDependencyTests(unittest.TestCase):
    def test_python_is_declared_for_corpus_tests(self):
        rules = (ROOT / "debian/rules").read_text()
        makefile = (ROOT / "GNUmakefile").read_text()
        control = (ROOT / "debian/control").read_text()

        self.assertIn("$(MAKE) -j2 test", rules)
        self.assertRegex(makefile, r"(?m)^test:\s+corpus-test\s*$")
        self.assertRegex(
            control,
            r"(?mi)^Build-Depends:.*(?:^|[ ,])python3(?:[ ,(]|$)",
            "debian/control must declare python3 because dh_auto_test runs corpus-test",
        )

    def test_builder_installs_declared_python_test_runtime(self):
        dockerfile = (ROOT / "tests/packaging/Dockerfile.builder").read_text()
        install_line = next(
            (line for line in dockerfile.splitlines() if "apt-get install" in line),
            "",
        )
        self.assertRegex(
            install_line,
            r"(?:^|\s)python3(?:\s|$)",
            "Debian 12 builder must install python3 before dpkg-buildpackage runs tests",
        )


if __name__ == "__main__":
    unittest.main()
