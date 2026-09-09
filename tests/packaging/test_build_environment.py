#!/usr/bin/env python3
"""Keep Debian's declared and CI build environments aligned with build tests."""

import re
import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def debian_build_dependencies() -> set[str]:
    control = (ROOT / "debian/control").read_text(encoding="utf-8")
    match = re.search(r"^Build-Depends:\s*(.+)$", control, re.MULTILINE)
    if match is None:
        return set()
    return {
        re.split(r"\s|\(", dependency.strip(), maxsplit=1)[0]
        for dependency in match.group(1).split(",")
    }


def builder_packages() -> set[str]:
    dockerfile = (ROOT / "tests/packaging/Dockerfile.builder").read_text(
        encoding="utf-8"
    )
    logical_lines = dockerfile.replace("\\\n", " ")
    install = re.search(r"apt-get install\s+-y\s+--no-install-recommends\s+(.+?)\s+&&", logical_lines)
    if install is None:
        return set()
    return set(shlex.split(install.group(1)))


class BuildEnvironmentTests(unittest.TestCase):
    def test_debian_build_declares_corpus_test_interpreter(self):
        self.assertIn("python3", debian_build_dependencies())

    def test_ci_builder_installs_corpus_test_interpreter(self):
        self.assertIn("python3", builder_packages())


if __name__ == "__main__":
    unittest.main()
