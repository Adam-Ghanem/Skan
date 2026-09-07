from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


class CorpusCliTests(unittest.TestCase):
    def test_stats_command_is_machine_readable(self) -> None:
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run([sys.executable, "-m", "tools.corpus.cli", "stats", "--root", str(root)], check=True, capture_output=True, text=True)
        parsed = json.loads(result.stdout)
        self.assertIn("total_records", parsed)
        self.assertIn("detection_records", parsed)
        self.assertIn("metadata_records", parsed)


if __name__ == "__main__":
    unittest.main()
