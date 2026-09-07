from __future__ import annotations

import unittest

from tools.corpus.benchmark import Observation, benchmark, better_than_nmap_gate, parse_nmap_xml


class BenchmarkTests(unittest.TestCase):
    def test_metrics_are_truth_labelled_and_claim_gate_is_strict(self) -> None:
        truth = {
            "a": Observation("a", "http", "nginx", "1.25", None, None),
            "b": Observation("b", "ssh", "openssh", "9.6", None, None),
        }
        skan = {
            "a": Observation("a", "http", "nginx", "1.25", None, None),
            "b": Observation("b", "ssh", "openssh", "9.6", None, None),
        }
        nmap = {"a": Observation("a", "http", "nginx", "1.25", None, None)}
        report = benchmark(truth, skan, nmap)
        self.assertEqual(report["skan"]["product_precision"], 1.0)
        self.assertEqual(report["skan"]["product_recall"], 1.0)
        self.assertEqual(report["nmap"]["product_recall"], 0.5)
        self.assertTrue(better_than_nmap_gate(report, metadata_complete=True))
        self.assertFalse(better_than_nmap_gate(report, metadata_complete=False))

    def test_nmap_parser_returns_observations_not_canonical_records(self) -> None:
        xml = '<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.25"/></port></ports></host></nmaprun>'
        result = parse_nmap_xml(xml)
        self.assertEqual(len(result), 1)
        observation = next(iter(result.values()))
        self.assertIsInstance(observation, Observation)
        self.assertEqual(observation.product, "nginx")
        self.assertFalse(hasattr(observation, "provenance"))


if __name__ == "__main__":
    unittest.main()
