import tempfile
import unittest
from pathlib import Path

from tools.corpus.runtime_udp_db import emit_udp_db, parse_udp_db


UDP_FIXTURE = """# name port protocol max payload
probe DNS 53 dns 512 123401000001000000000000
probe SNMP 161 snmp 2048 301002010104067075626c6963
probe DEFAULT 0 generic 512 00
"""


class RuntimeUdpDbTests(unittest.TestCase):
    def parse_fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "udp-probes.db"
        path.write_text(UDP_FIXTURE, encoding="utf-8")
        return path, parse_udp_db(path)

    def test_preserves_runtime_udp_fields_and_order(self):
        _, records = self.parse_fixture()
        self.assertEqual([record.probe_id for record in records], ["DNS", "SNMP", "DEFAULT"])
        self.assertEqual([record.probe_order for record in records], [0, 1, 2])
        dns = records[0]
        self.assertEqual(dns.kind, "udp_probe")
        self.assertEqual(dns.transport, "udp")
        self.assertEqual(dns.ports, (53,))
        self.assertEqual(dns.protocol_hint, "dns")
        self.assertEqual(dns.max_response_bytes, 512)
        self.assertEqual(dns.probe_payload_hex, "123401000001000000000000")
        self.assertEqual(records[-1].ports, (0,))

    def test_parse_emit_parse_is_semantically_exact_and_deterministic(self):
        _, records = self.parse_fixture()
        emitted = emit_udp_db(records)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "generated.db"
            path.write_text(emitted, encoding="utf-8")
            reparsed = parse_udp_db(path)
        self.assertEqual(reparsed, records)
        self.assertEqual(emitted, emit_udp_db(list(reversed(records))))

    def test_rejects_malformed_or_odd_hex_with_line_context(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broken.db"
            path.write_text("probe DNS 53 dns 512 abc\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"broken\.db:1.*payload"):
                parse_udp_db(path)

    def test_rejects_duplicate_probe_name(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broken.db"
            path.write_text(
                "probe DNS 53 dns 512 00\nprobe DNS 54 dns 512 00\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate probe"):
                parse_udp_db(path)


if __name__ == "__main__":
    unittest.main()
