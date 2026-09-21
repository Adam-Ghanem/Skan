from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.comparison.model import Endpoint, RunStatus
from tools.comparison.parsers import ResultParseError, parse_nmap_xml, parse_skan_json


FIXTURES = Path(__file__).with_name("fixtures")


class ScannerResultParserTests(unittest.TestCase):
    def test_equivalent_fixtures_normalize_the_same_evidence(self) -> None:
        skan = parse_skan_json((FIXTURES / "skan-valid.json").read_bytes())
        nmap = parse_nmap_xml((FIXTURES / "nmap-valid.xml").read_bytes())

        self.assertEqual(skan.status, RunStatus.COMPLETE)
        self.assertEqual(nmap.status, RunStatus.COMPLETE)
        self.assertEqual(skan.version, "0.1.1")
        self.assertEqual(nmap.version, "7.95")
        self.assertAlmostEqual(skan.elapsed_seconds or 0, 1.234)
        self.assertAlmostEqual(nmap.elapsed_seconds or 0, 1.234)
        self.assertEqual(
            [(item.endpoint, item.state, item.service, item.product, item.version) for item in skan.observations],
            [(item.endpoint, item.state, item.service, item.product, item.version) for item in nmap.observations],
        )
        self.assertEqual(skan.observations[0].endpoint, Endpoint("127.0.0.1", "tcp", 8080))
        self.assertEqual(skan.observations[0].confidence, 0.98)
        self.assertEqual(nmap.observations[0].confidence, 1.0)

    def test_skan_rejects_duplicate_endpoints_and_service_without_port(self) -> None:
        document = json.loads((FIXTURES / "skan-valid.json").read_text(encoding="utf-8"))
        document["hosts"][0]["ports"].append(dict(document["hosts"][0]["ports"][0]))
        with self.assertRaisesRegex(ResultParseError, "duplicate endpoint"):
            parse_skan_json(json.dumps(document).encode())

        document = json.loads((FIXTURES / "skan-valid.json").read_text(encoding="utf-8"))
        document["hosts"][0]["services"][0]["port"] = 9090
        with self.assertRaisesRegex(ResultParseError, "without a port observation"):
            parse_skan_json(json.dumps(document).encode())

    def test_nmap_rejects_duplicate_endpoints(self) -> None:
        data = (FIXTURES / "nmap-valid.xml").read_bytes()
        duplicate = data.replace(
            b"</ports>",
            b'<port protocol="tcp" portid="8080"><state state="open" reason="x" /></port></ports>',
        )
        with self.assertRaisesRegex(ResultParseError, "duplicate endpoint"):
            parse_nmap_xml(duplicate)

    def test_nmap_preserves_extraport_state_summaries_for_later_expansion(self) -> None:
        payload = b'''<nmaprun scanner="nmap" version="7.95">
          <host><address addr="127.0.0.1" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/></port>
            <extraports state="closed" count="2"><extrareasons reason="reset" count="2"/></extraports>
          </ports></host><runstats><finished elapsed="0.5"/></runstats>
        </nmaprun>'''
        run = parse_nmap_xml(payload)
        self.assertEqual(
            [(item.target, item.state, item.count, item.reason) for item in run.state_summaries],
            [("127.0.0.1", "closed", 2, "reset")],
        )

    def test_rejects_malformed_missing_and_unsafe_documents(self) -> None:
        bad_skan = [
            b"{",
            b'{"scanner":{"name":"Skan","version":"x"},"scan":{},"hosts":[]}',
            b'{"scanner":{"name":"Skan","name":"other","version":"x"},"scan":{"duration_ms":1},"hosts":[]}',
        ]
        for payload in bad_skan:
            with self.subTest(payload=payload), self.assertRaises(ResultParseError):
                parse_skan_json(payload)

        bad_nmap = [
            b"<nmaprun>",
            b'<nmaprun scanner="nmap" version="7"><runstats /></nmaprun>',
            b'<!DOCTYPE x [<!ENTITY y "boom">]><nmaprun scanner="nmap" version="7"><runstats><finished elapsed="1"/></runstats></nmaprun>',
            b'<nmaprun scanner="nmap" version="7"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><extraports state="closed" count="0"/></ports></host><runstats><finished elapsed="1"/></runstats></nmaprun>',
        ]
        for payload in bad_nmap:
            with self.subTest(payload=payload), self.assertRaises(ResultParseError):
                parse_nmap_xml(payload)

    def test_rejects_oversized_results_before_parsing(self) -> None:
        oversized = b" " * ((4 << 20) + 1)
        with self.assertRaisesRegex(ResultParseError, "size limit"):
            parse_skan_json(oversized)
        with self.assertRaisesRegex(ResultParseError, "size limit"):
            parse_nmap_xml(oversized)


if __name__ == "__main__":
    unittest.main()
