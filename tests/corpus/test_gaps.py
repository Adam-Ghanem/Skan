from __future__ import annotations

import unittest

from tools.corpus.benchmark import Observation
from tools.corpus.gaps import build_gap_report


class GapRegistryTests(unittest.TestCase):
    def test_gap_report_contains_observation_not_nmap_signature_material(self) -> None:
        truth = {"x": Observation("x", "ftp", "ExampleFTP", "2", None, None)}
        skan = {}
        nmap = {"x": Observation("x", "ftp", "ExampleFTP", "2", None, None)}
        report = build_gap_report(truth, skan, nmap)
        self.assertEqual(len(report), 1)
        gap = report[0]
        self.assertEqual(gap["expected_product"], "ExampleFTP")
        rendered = str(gap).lower()
        self.assertNotIn("matcher", rendered)
        self.assertNotIn("signature", rendered)
        self.assertNotIn("probe_bytes", rendered)


if __name__ == "__main__":
    unittest.main()
