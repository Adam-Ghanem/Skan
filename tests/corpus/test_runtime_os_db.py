import tempfile
import unittest
from pathlib import Path

from tools.corpus.runtime_os_db import emit_os_db, parse_os_db


IPV4_FIXTURE = """# current v4 style
Fingerprint SkanLinuxGeneric
Class Skan | Linux | 5.x+ | general-purpose
TTL=64
DF=Y
WINDOW=64240
TCP_OPTIONS=MSS,SACK,TS,NOP,WS
CUSTOM_SIGNAL=kept-verbatim

Fingerprint SkanEmbeddedGeneric
Class Skan | Embedded | generic | network-device
TTL_RANGE=32-128
WINDOW_RANGE=1024-8192
RESPONSE_BEHAVIOR=RST
"""

IPV6_FIXTURE = """Fingerprint SkanIPv6LinuxGeneric
ID=skan-v6-linux-generic
SPECIFICITY=13
ADDRESS_FAMILY=IPv6
Class Skan | Linux IPv6 | generic | general-purpose
TTL=64
WINDOW=64240
TCP_OPTIONS=MSS,SACK,TS,NOP,WS
RESPONSE_PRESENCE=YES
"""


class RuntimeOsDbTests(unittest.TestCase):
    def write_fixture(self, name: str, text: str) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_parses_ipv4_class_features_unknown_keys_and_order(self):
        path = self.write_fixture("os-fingerprints.db", IPV4_FIXTURE)
        records = parse_os_db(path, "ipv4")
        self.assertEqual([record.fingerprint_name for record in records], ["SkanLinuxGeneric", "SkanEmbeddedGeneric"])
        self.assertEqual([record.probe_order for record in records], [0, 1])
        linux = records[0]
        self.assertEqual(linux.address_family, "ipv4")
        self.assertEqual(linux.vendor, "Skan")
        self.assertEqual(linux.os_family, "Linux")
        self.assertEqual(linux.os_generation, "5.x+")
        self.assertEqual(linux.device_type, "general-purpose")
        self.assertIn(("CUSTOM_SIGNAL", "kept-verbatim"), linux.os_features)
        self.assertIn(("TCP_OPTIONS", "MSS,SACK,TS,NOP,WS"), linux.os_features)
        self.assertIn(("TTL_RANGE", "32-128"), records[1].os_features)

    def test_parses_ipv6_native_id_specificity_and_declared_family(self):
        path = self.write_fixture("os-fingerprints-v6.db", IPV6_FIXTURE)
        records = parse_os_db(path, "ipv6")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.fingerprint_native_id, "skan-v6-linux-generic")
        self.assertEqual(record.specificity, 13)
        self.assertEqual(record.address_family, "ipv6")

    def test_parse_emit_parse_is_semantically_exact_and_deterministic(self):
        for family, name, text in (
            ("ipv4", "v4.db", IPV4_FIXTURE),
            ("ipv6", "v6.db", IPV6_FIXTURE),
        ):
            with self.subTest(family=family):
                path = self.write_fixture(name, text)
                records = parse_os_db(path, family)
                emitted = emit_os_db(records)
                generated = self.write_fixture("generated.db", emitted)
                reparsed = parse_os_db(generated, family)
                self.assertEqual(reparsed, records)
                self.assertEqual(emitted, emit_os_db(list(reversed(records))))

    def test_rejects_address_family_mismatch(self):
        path = self.write_fixture("bad.db", IPV6_FIXTURE)
        with self.assertRaisesRegex(ValueError, r"bad\.db:4.*ADDRESS_FAMILY"):
            parse_os_db(path, "ipv4")

    def test_rejects_duplicate_feature_key_with_line_context(self):
        path = self.write_fixture(
            "bad.db",
            "Fingerprint A\nClass Skan | Linux | generic | general-purpose\nTTL=64\nTTL=128\n",
        )
        with self.assertRaisesRegex(ValueError, r"bad\.db:4.*duplicate feature"):
            parse_os_db(path, "ipv4")

    def test_rejects_malformed_class(self):
        path = self.write_fixture("bad.db", "Fingerprint A\nClass Skan | Linux\nTTL=64\n")
        with self.assertRaisesRegex(ValueError, r"bad\.db:2.*Class"):
            parse_os_db(path, "ipv4")


if __name__ == "__main__":
    unittest.main()
