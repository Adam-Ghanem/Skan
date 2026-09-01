#!/usr/bin/env python3
"""Behavioral tests for the GitHub Actions supply-chain policy."""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate_workflow_policy.py"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"


class WorkflowPolicyTests(unittest.TestCase):
    def validate(self, workflow: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workflow_path = Path(temporary_directory) / "ci.yml"
            workflow_path.write_text(textwrap.dedent(workflow), encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), str(workflow_path)],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_accepts_pinned_action_and_hardened_checkout(self) -> None:
        result = self.validate(
            f"""
            name: fixture
            jobs:
              test:
                steps:
                  - name: Checkout
                    uses: actions/checkout@{CHECKOUT_SHA}
                    with:
                      persist-credentials: false
            """
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unpinned_action_reference(self) -> None:
        result = self.validate(
            """
            name: fixture
            jobs:
              test:
                steps:
                  - uses: actions/checkout@v4
                    with:
                      persist-credentials: false
            """
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must use a 40-character commit SHA", result.stderr)

    def test_rejects_checkout_that_persists_credentials(self) -> None:
        result = self.validate(
            f"""
            name: fixture
            jobs:
              test:
                steps:
                  - uses: actions/checkout@{CHECKOUT_SHA}
            """
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("persist-credentials: false", result.stderr)


if __name__ == "__main__":
    unittest.main()
