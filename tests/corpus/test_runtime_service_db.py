import tempfile
import unittest
from pathlib import Path

from tools.corpus.runtime_service_db import emit_service_db, parse_service_db


SERVICE_FIXTURE = r'''# first-party runtime fixture
Probe TCP HTTPGet rarity=1 priority=95 timeout=1500 ports=80,8080 fallback=GenericBanner
send "GET / HTTP/1.0\r\nX-Test: \"q\"\r\n\x00\\\t"
match type=regex pattern="^HTTP/([0-9.]+)[\\s\\S]*" service=http product="HTTP Server" version="$1" extra="proto $1" hostname="$2" tunnel=tls confidence=0.96
softmatch type=prefix pattern="HTTP/" service=http product=HTTP confidence=0.70
match type=suffix pattern="END" service=end product=End confidence=0.50
match type=substring pattern="hello world" service=hello product="Hello World" confidence=0.60
match type=exact pattern="OK#READY" service=ok product=Okay confidence=0.80 # outside comment

Probe TCP GenericBanner rarity=5 priority=10 timeout=1000
send ""
match type=exact pattern="OK" service=generic product=Generic confidence=0.55
'''


class RuntimeServiceDbTests(unittest.TestCase):
    def parse_fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "service-probes.db"
        path.write_text(SERVICE_FIXTURE, encoding="utf-8")
        return path, parse_service_db(path)

    def test_parses_probe_payload_order_and_fallbacks(self):
        _, records = self.parse_fixture()
        probes = [record for record in records if record.kind == "active_probe"]
        self.assertEqual([probe.probe_id for probe in probes], ["HTTPGet", "GenericBanner"])
        first = probes[0]
        self.assertEqual(first.transport, "tcp")
        self.assertEqual(first.rarity, 1)
        self.assertEqual(first.probe_priority, 95)
        self.assertEqual(first.probe_timeout_ms, 1500)
        self.assertEqual(first.ports, (80, 8080))
        self.assertEqual(first.fallback_probe_ids, ("GenericBanner",))
        self.assertEqual(first.probe_order, 0)
        self.assertEqual(
            bytes.fromhex(first.probe_payload_hex),
            b'GET / HTTP/1.0\r\nX-Test: "q"\r\n\x00\\\t',
        )
        self.assertEqual(probes[1].probe_payload_hex, "")
        self.assertEqual(probes[1].probe_order, 1)

    def test_parses_all_match_types_strengths_templates_and_order(self):
        _, records = self.parse_fixture()
        rules = [
            record
            for record in records
            if record.kind == "service_matcher" and record.probe_id == "HTTPGet"
        ]
        self.assertEqual(
            [rule.matcher_type for rule in rules],
            ["regex", "prefix", "suffix", "substring", "exact"],
        )
        self.assertEqual([rule.rule_order for rule in rules], [0, 1, 2, 3, 4])
        self.assertEqual([rule.match_strength for rule in rules], ["hard", "soft", "hard", "hard", "hard"])
        regex = rules[0]
        self.assertEqual(regex.matcher_expression, r"^HTTP/([0-9.]+)[\s\S]*")
        self.assertEqual(regex.product, "HTTP Server")
        self.assertEqual(regex.version, "$1")
        self.assertEqual(regex.extra_template, "proto $1")
        self.assertEqual(regex.hostname_template, "$2")
        self.assertEqual(regex.tunnel_template, "tls")
        self.assertEqual(regex.confidence, 0.96)
        self.assertEqual(regex.probe_order, 0)
        self.assertEqual(rules[-1].matcher_expression, "OK#READY")

    def test_provenance_is_first_party_and_logically_hashed(self):
        _, records = self.parse_fixture()
        contribution = records[0].provenance[0]
        self.assertEqual(contribution.source_id, "skan-first-party")
        self.assertEqual(contribution.source_revision, "repository")
        self.assertEqual(contribution.source_license, "MIT")
        self.assertRegex(contribution.source_hash, r"^sha256:[0-9a-f]{64}$")

    def test_parse_emit_parse_is_semantically_exact(self):
        _, records = self.parse_fixture()
        emitted = emit_service_db(records)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "generated.db"
            path.write_text(emitted, encoding="utf-8")
            reparsed = parse_service_db(path)
        self.assertEqual(reparsed, records)
        self.assertEqual(emitted, emit_service_db(list(reversed(records))))

    def test_rejects_unknown_fallback_with_line_context(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broken.db"
            path.write_text(
                'Probe TCP A rarity=1 priority=50 timeout=1000 fallback=Missing\nsend ""\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, r"broken\.db:1.*fallback"):
                parse_service_db(path)

    def test_rejects_duplicate_probe_name(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broken.db"
            path.write_text(
                'Probe TCP A rarity=1 priority=50 timeout=1000\nsend ""\n'
                'Probe TCP A rarity=1 priority=50 timeout=1000\nsend ""\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate probe"):
                parse_service_db(path)


if __name__ == "__main__":
    unittest.main()
