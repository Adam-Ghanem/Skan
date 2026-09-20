from __future__ import annotations

from pathlib import Path
import unittest

from tools.corpus.performance import measure_corpus


class CorpusPerformanceTests(unittest.TestCase):
    def test_reports_sizes_load_time_peak_memory_and_class_counts(self) -> None:
        root = Path(__file__).resolve().parents[2]
        report = measure_corpus(root)
        self.assertGreater(report["canonical_bytes"], 1_000_000)
        self.assertGreater(report["first_party_runtime_bytes"], 0)
        self.assertGreater(report["load_seconds"], 0.0)
        self.assertGreater(report["peak_rss_mib"], 0.0)
        self.assertGreater(report["total_records"], 10_000)
        self.assertGreater(report["detection_records"], 10_000)
        self.assertGreater(report["metadata_records"], 1_000)
        self.assertEqual(report["unresolved_conflicts"], 0)
        self.assertIn("records_by_kind", report)


if __name__ == "__main__":
    unittest.main()
