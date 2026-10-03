"""Exercise transfer-workflow push authentication without contacting GitHub."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


class MaterializePushTests(unittest.TestCase):
    def test_push_authenticates_without_checkout_credentials(self) -> None:
        workflow = (ROOT / ".github/workflows/materialize-codex-patch.yml").read_text()
        push_step = workflow.split("      - name: Push materialized commit\n", 1)[1]
        run = push_step.split("        run:", 1)[1].lstrip()
        script = textwrap.dedent(run[1:] if run.startswith("|") else run)
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for command, body in {
                "gh": 'test "$1 $2" = "auth setup-git" && test -n "$GH_TOKEN" && touch "$AUTH_MARKER"',
                "git": 'test -f "$AUTH_MARKER" || exit 41\ntest "$*" = "push origin HEAD:refs/heads/codex-materialized"',
            }.items():
                executable = directory / command
                executable.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
                executable.chmod(0o755)
            environment = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"],
                               GH_TOKEN="fixture-token", AUTH_MARKER=str(directory / "authenticated"))
            result = subprocess.run(["bash", "-eo", "pipefail", "-c", script], env=environment,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("GH_TOKEN: ${{ github.token }}", push_step)


if __name__ == "__main__":
    unittest.main()
