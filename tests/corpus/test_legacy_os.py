from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.legacy_os import (
    LegacyOSError,
    compile_legacy_os,
    load_legacy_os,
    parse_legacy_os,
    semantic_os_ids,
    verify_os_round_trip,
)
from tools.corpus.model import OSFingerprintSemantics
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
SOURCES = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")
LEGACY_V4 = ROOT / "data" / "os-fingerprints.db"
LEGACY_V6 = ROOT / "data" / "os-fingerprints-v6.db"


IPV4_SYNTHETIC = """\
# synthetic IPv4 fingerprint
Fingerprint DemoLinux
ID=skan-v4-demo-linux
SPECIFICITY=11
ADDRESS_FAMILY=IPv4
Class Example | ExampleOS | modern | appliance
TTL_RANGE=45-64
DF=Y
WINDOW=64240
MSS=1460
WSCALE=7
SACK=Y
TIMESTAMP=N
TCP_OPTIONS=MSS,SACK,TIMESTAMP,NOP,WSCALE
RESPONSE_BEHAVIOR=SYN_ACK
RESPONSE_PRESENCE=YES
ICMP_TTL_RANGE=45-64
"""


class LegacyOSMigrationTests(unittest.TestCase):
    def test_parses_ipv4_runtime_semantics(self) -> None:
        records = parse_legacy_os(IPV4_SYNTHETIC, SOURCES, expected_family="ipv4")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.kind, "os_fingerprint")
        self.assertIsInstance(record.body, OSFingerprintSemantics)
        body = record.body
        assert isinstance(body, OSFingerprintSemantics)
        self.assertEqual(body.runtime_id, "skan-v4-demo-linux")
        self.assertEqual(body.name, "DemoLinux")
        self.assertEqual(body.vendor, "Example")
        self.assertEqual(body.os_family, "ExampleOS")
        self.assertEqual(body.os_generation, "modern")
        self.assertEqual(body.device_type, "appliance")
        self.assertEqual(body.address_family, "ipv4")
        self.assertEqual(body.specificity, 11)
        signatures = {signature.field: signature for signature in body.signatures}
        self.assertEqual(signatures["ttl"].operator, "range")
        self.assertEqual(signatures["ttl"].value, (45, 64))
        self.assertEqual(signatures["dont_fragment"].value, True)
        self.assertEqual(
            signatures["tcp_options"].value,
            ("MSS", "SACK", "TS", "NOP", "WS"),
        )
        self.assertEqual(signatures["response_behavior"].value, "SYN_ACK")

    def test_materializes_runtime_defaults_without_changing_semantics(self) -> None:
        text = "Fingerprint Bare\nClass Example | BareOS\nTTL=64\n"
        records = parse_legacy_os(text, SOURCES, expected_family="ipv4")
        body = records[0].body
        assert isinstance(body, OSFingerprintSemantics)
        self.assertEqual(body.runtime_id, "Bare")
        self.assertEqual(body.specificity, 1)
        self.assertEqual(body.address_family, "ipv4")

        generated = compile_legacy_os(records, SOURCES, address_family="ipv4")
        reparsed = parse_legacy_os(generated, SOURCES, expected_family="ipv4")
        verify_os_round_trip(records, reparsed)

    def test_ipv6_requires_explicit_family_and_rejects_ipv4_only_df(self) -> None:
        missing_family = "Fingerprint V6\nClass Example | IPv6\nTTL=64\n"
        with self.assertRaisesRegex(LegacyOSError, "ADDRESS_FAMILY"):
            parse_legacy_os(missing_family, SOURCES, expected_family="ipv6")

        invalid_df = (
            "Fingerprint V6\nADDRESS_FAMILY=IPv6\n"
            "Class Example | IPv6\nDF=Y\n"
        )
        with self.assertRaisesRegex(LegacyOSError, "IPv6 fingerprints cannot contain dont_fragment"):
            parse_legacy_os(invalid_df, SOURCES, expected_family="ipv6")

    def test_rejects_family_mismatch_duplicate_fields_and_duplicate_identity(self) -> None:
        mismatch = (
            "Fingerprint Demo\nADDRESS_FAMILY=IPv6\n"
            "Class Example | Demo\nTTL=64\n"
        )
        with self.assertRaisesRegex(LegacyOSError, "address family"):
            parse_legacy_os(mismatch, SOURCES, expected_family="ipv4")

        duplicate_field = (
            "Fingerprint Demo\nADDRESS_FAMILY=IPv4\nClass Example | Demo\n"
            "TTL=64\nTTL_RANGE=45-64\n"
        )
        with self.assertRaisesRegex(LegacyOSError, "duplicate signature field"):
            parse_legacy_os(duplicate_field, SOURCES, expected_family="ipv4")

        duplicate_name = IPV4_SYNTHETIC + IPV4_SYNTHETIC
        with self.assertRaisesRegex(LegacyOSError, "duplicate fingerprint name"):
            parse_legacy_os(duplicate_name, SOURCES, expected_family="ipv4")

    def test_repository_ipv4_and_ipv6_corpora_round_trip_without_semantic_drift(self) -> None:
        ipv4 = load_legacy_os(LEGACY_V4, SOURCES, expected_family="ipv4")
        ipv6 = load_legacy_os(LEGACY_V6, SOURCES, expected_family="ipv6")
        self.assertGreaterEqual(len(ipv4), 20)
        self.assertGreaterEqual(len(ipv6), 20)
        self.assertLessEqual(len(ipv4) + len(ipv6), 256)
        self.assertTrue(all(record.body.address_family == "ipv4" for record in ipv4))  # type: ignore[union-attr]
        self.assertTrue(all(record.body.address_family == "ipv6" for record in ipv6))  # type: ignore[union-attr]

        generated_v4 = compile_legacy_os(ipv4, SOURCES, address_family="ipv4")
        generated_v6 = compile_legacy_os(ipv6, SOURCES, address_family="ipv6")
        actual_v4 = parse_legacy_os(generated_v4, SOURCES, expected_family="ipv4")
        actual_v6 = parse_legacy_os(generated_v6, SOURCES, expected_family="ipv6")
        verify_os_round_trip(ipv4, actual_v4)
        verify_os_round_trip(ipv6, actual_v6)
        self.assertEqual(generated_v4, compile_legacy_os(actual_v4, SOURCES, address_family="ipv4"))
        self.assertEqual(generated_v6, compile_legacy_os(actual_v6, SOURCES, address_family="ipv6"))

    def test_jsonl_round_trip_preserves_combined_semantic_ids(self) -> None:
        expected = (
            *load_legacy_os(LEGACY_V4, SOURCES, expected_family="ipv4"),
            *load_legacy_os(LEGACY_V6, SOURCES, expected_family="ipv6"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "os.jsonl"
            write_jsonl(path, expected, SOURCES)
            actual = load_jsonl(path, SOURCES, expected_kind="os_fingerprint")
        self.assertEqual(semantic_os_ids(expected), semantic_os_ids(actual))


if __name__ == "__main__":
    unittest.main()
