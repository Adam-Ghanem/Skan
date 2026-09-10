from __future__ import annotations

from pathlib import Path
import unittest

from tools.corpus.model import (
    ActiveProbeSemantics,
    OSFingerprintSemantics,
    ServiceMatcherSemantics,
    UDPProbeSemantics,
)
from tools.corpus.runtime import (
    ImportContext,
    RuntimeCorpusError,
    parse_os_runtime,
    parse_service_runtime,
    parse_udp_runtime,
)
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
POLICY = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")[
    "skan-first-party"
]
CONTEXT = ImportContext(POLICY, "data/service-probes.db")
UDP_CONTEXT = ImportContext(POLICY, "data/udp-probes.db")
OS4_CONTEXT = ImportContext(POLICY, "data/os-fingerprints.db")
OS6_CONTEXT = ImportContext(POLICY, "data/os-fingerprints-v6.db")


SERVICE_RUNTIME = b'''\
# Synthetic project-owned runtime fixture.
Probe TCP GenericBanner rarity=2 priority=40 protocol=tcp
send "\\r\\n"
softmatch type=prefix pattern="220 " service=banner product="Generic Server" confidence=0.40

Probe TCP HTTPGet rarity=1 priority=100 timeout=1500 ports=80,443 fallback=GenericBanner protocol=tcp
send "GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n"
match type=regex pattern="^HTTP/([0-9.]+).*Server: Apache/([0-9.]+)" service=http product=Apache version="$2" extra=Ubuntu hostname="$1" tunnel=tls confidence=0.99
match type=prefix pattern="\\x16\\x03" service=tls product=TLS confidence=0.75
match type=regex pattern="\\x00ABC" service=binary product=Binary confidence=0.70
'''

UDP_RUNTIME = b'''\
# Synthetic project-owned UDP fixture.
probe DNS 53 dns 512 1234
probe NTP 123 ntp 2048 1B00
probe DEFAULT 0 generic 512 00
'''

OS_RUNTIME = b'''\
Fingerprint CompleteStack
ID=complete-stack-v4
SPECIFICITY=20
ADDRESS_FAMILY=IPv4
Class Example Vendor | Example Family | 1.0 | appliance
TTL=64
WINDOW_RANGE=1024-4096
MSS=1460
WSCALE=7
TCP_FLAGS=18
ICMP_TTL=64
ICMP_TYPE=3
ICMP_CODE=3
UDP_PAYLOAD_LENGTH=42
DF=YES
SACK=0
TIMESTAMP=1
TCP_OPTIONS=MSS,WSCALE,SACK,TIMESTAMP,NOP
UDP_RESPONSE_BEHAVIOR=UDP_RESPONSE
RESPONSE_PRESENCE=N
ACK_BEHAVIOR=ACKNOWLEDGES_SYN
SEQUENCE_BEHAVIOR=INCREMENTAL
RESPONSE_BEHAVIOR=SYN_ACK
'''

OS_RUNTIME_HASH = "sha256:94dcb236b214d2dcb9c50b7edda1f2e8a59461586be620eb2bd1860f9dbc3ef5"


class RuntimeServiceImportTests(unittest.TestCase):
    def parse(self, value: bytes = SERVICE_RUNTIME):
        return parse_service_runtime(value, CONTEXT)

    def assert_rejected(self, value: bytes, message: str) -> None:
        with self.assertRaisesRegex(RuntimeCorpusError, message):
            self.parse(value)

    def test_imports_probe_payload_matchers_order_and_provenance(self) -> None:
        records = self.parse()
        probes = [record for record in records if record.kind == "active_probe"]
        matchers = [record for record in records if record.kind == "service_matcher"]

        self.assertEqual(len(probes), 2)
        self.assertEqual(len(matchers), 4)
        self.assertTrue(all(record.status == "verified" for record in records))
        self.assertTrue(all(record.id.startswith("skan-db-v2-") for record in records))

        generic = probes[0].body
        http = probes[1].body
        self.assertIsInstance(generic, ActiveProbeSemantics)
        self.assertIsInstance(http, ActiveProbeSemantics)
        self.assertEqual(generic.declaration_order, 0)
        self.assertEqual(generic.payload_hex, "0d0a")
        self.assertEqual(http.declaration_order, 1)
        self.assertEqual(http.transport, "tcp")
        self.assertEqual(http.payload_hex, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".hex())
        self.assertEqual(http.ports, (80, 443))
        self.assertEqual(http.timeout_ms, 1500)
        self.assertEqual(http.fallback_probe_names, ("GenericBanner",))

        apache = matchers[1].body
        tls = matchers[2].body
        binary_regex = matchers[3].body
        self.assertIsInstance(apache, ServiceMatcherSemantics)
        self.assertEqual(apache.rule_order, 0)
        self.assertEqual(apache.pattern, "^HTTP/([0-9.]+).*Server: Apache/([0-9.]+)")
        self.assertIsNone(apache.pattern_hex)
        self.assertEqual(apache.product, "Apache")
        self.assertEqual(apache.version_template, "$2")
        self.assertEqual(apache.extra, "Ubuntu")
        self.assertEqual(apache.hostname_template, "$1")
        self.assertEqual(apache.tunnel, "tls")
        self.assertEqual(tls.rule_order, 1)
        self.assertEqual(tls.pattern_hex, "1603")
        self.assertEqual(binary_regex.rule_order, 2)
        self.assertIsNone(binary_regex.pattern)
        self.assertEqual(binary_regex.pattern_hex, "00414243")

        identities = [record.provenance[0].source_record_id for record in records]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertTrue(all(identity.startswith("data/service-probes.db:") for identity in identities))
        self.assertTrue(
            all(record.provenance[0].record_hash.startswith("sha256:") for record in records)
        )
        self.assertTrue(all(record.provenance[0].snapshot_hash is None for record in records))

    def test_import_is_deterministic(self) -> None:
        first = self.parse()
        second = self.parse()
        self.assertEqual(first, second)
        self.assertEqual(tuple(record.id for record in first), tuple(record.id for record in second))

    def test_imports_current_first_party_service_runtime(self) -> None:
        records = self.parse((ROOT / "data" / "service-probes.db").read_bytes())
        self.assertEqual(sum(record.kind == "active_probe" for record in records), 36)
        self.assertEqual(sum(record.kind == "service_matcher" for record in records), 136)

    def test_rejects_unknown_directives_and_malformed_quotes(self) -> None:
        self.assert_rejected(
            b'Probe TCP One\nsend "PING"\nexecute "bad"\n',
            "unknown directive.*execute",
        )
        self.assert_rejected(b'Probe TCP One\nsend "unterminated\n', "unterminated quote")

    def test_rejects_duplicate_names_missing_payload_and_unresolved_fallback(self) -> None:
        self.assert_rejected(
            b'Probe TCP Same\nsend "A"\nProbe TCP Same\nsend "B"\n',
            "duplicate probe name.*Same",
        )
        self.assert_rejected(b"Probe TCP Missing\n", "missing send directive.*Missing")
        self.assert_rejected(
            b'Probe TCP One fallback=Absent\nsend "A"\n',
            "unresolved fallback.*Absent",
        )

    def test_rejects_duplicate_fields_invalid_cross_transport_fallback_and_rule_fields(self) -> None:
        self.assert_rejected(
            b'Probe TCP One rarity=1 rarity=2\nsend "A"\n',
            "duplicate Probe field.*rarity",
        )
        self.assert_rejected(
            b'Probe TCP One fallback=Two\nsend "A"\nProbe UDP Two\nsend "B"\n',
            "cross-transport fallback.*Two",
        )
        self.assert_rejected(
            b'Probe TCP One\nsend "A"\nmatch pattern="A" service=a confidence=0.5 confidence=0.6\n',
            "duplicate match field.*confidence",
        )

    def test_rejects_invalid_ports_confidence_and_resource_overflow(self) -> None:
        self.assert_rejected(b'Probe TCP One ports=0\nsend "A"\n', "invalid ports")
        for confidence in (b"1.1", b"+0.5", b"0_5", b'" 0.5"'):
            with self.subTest(confidence=confidence):
                self.assert_rejected(
                    b'Probe TCP One\nsend "A"\nmatch pattern="A" service=a confidence='
                    + confidence
                    + b"\n",
                    "invalid confidence",
                )
        self.assert_rejected(b"#" + (b"x" * (16 * 1024)) + b"\n", "line 1 exceeds")
        self.assert_rejected(b"#" * ((1 << 20) + 1), "database exceeds")

    def test_malformed_hex_escape_is_preserved_like_the_runtime_parser(self) -> None:
        records = self.parse(b'Probe TCP One\nsend "\\x+1\\xG1"\n')
        probe = records[0].body
        self.assertIsInstance(probe, ActiveProbeSemantics)
        self.assertEqual(probe.payload_hex, b"\\x+1\\xG1".hex())

    def test_rejects_structurally_invalid_ecmascript_regex(self) -> None:
        for pattern in (
            b"(unclosed",
            b"[unclosed",
            b"unexpected)",
            b"*leading",
            b"[z-a]",
            b"a**",
            b"a++",
            b"a{2,1}",
        ):
            with self.subTest(pattern=pattern):
                self.assert_rejected(
                    b'Probe TCP One\nsend "A"\nmatch type=regex pattern="'
                    + pattern
                    + b'" service=a confidence=0.5\n',
                    "invalid ECMAScript regex",
                )

    def test_rejects_character_class_with_more_than_runtime_capture_bound_parentheses(self) -> None:
        self.assert_rejected(
            b'Probe TCP One\nsend "A"\nmatch type=regex pattern="['
            + (b"(" * 17)
            + b']" service=a confidence=0.5\n',
            "invalid ECMAScript regex",
        )

    def test_rejects_line_bounded_huge_decimal_with_typed_error(self) -> None:
        self.assert_rejected(
            b"Probe TCP One rarity=" + (b"9" * 5000) + b'\nsend "A"\n',
            "invalid rarity",
        )


class RuntimeUDPImportTests(unittest.TestCase):
    def parse(self, value: bytes = UDP_RUNTIME):
        return parse_udp_runtime(value, UDP_CONTEXT)

    def assert_rejected(self, value: bytes, message: str) -> None:
        with self.assertRaisesRegex(RuntimeCorpusError, message):
            self.parse(value)

    def test_imports_ordered_udp_records_and_required_default(self) -> None:
        records = self.parse()
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record.kind == "udp_probe" for record in records))
        self.assertEqual([record.body.name for record in records], ["DNS", "NTP", "DEFAULT"])

        dns, ntp, default = (record.body for record in records)
        self.assertIsInstance(dns, UDPProbeSemantics)
        self.assertEqual(dns.destination_port, 53)
        self.assertEqual(dns.protocol_hint, "dns")
        self.assertEqual(dns.max_response_bytes, 512)
        self.assertEqual(dns.payload_hex, "1234")
        self.assertEqual(dns.declaration_order, 0)
        self.assertEqual(ntp.payload_hex, "1b00")
        self.assertEqual(ntp.declaration_order, 1)
        self.assertEqual(default.destination_port, 0)
        self.assertEqual(default.name, "DEFAULT")
        self.assertEqual(default.declaration_order, 2)
        self.assertEqual(
            records[0].provenance[0].source_record_id,
            "data/udp-probes.db:probe:DNS",
        )

    def test_imports_current_first_party_udp_runtime(self) -> None:
        records = self.parse((ROOT / "data" / "udp-probes.db").read_bytes())
        self.assertEqual(len(records), 21)
        self.assertEqual(sum(record.body.destination_port == 0 for record in records), 1)
        self.assertEqual(records[-1].body.name, "DEFAULT")

    def test_rejects_duplicate_ports_names_unknown_syntax_and_missing_default(self) -> None:
        self.assert_rejected(
            b"probe One 53 x 1 00\nprobe Two 53 y 1 00\nprobe DEFAULT 0 generic 1 00\n",
            "duplicate UDP port.*53",
        )
        self.assert_rejected(
            b"probe One 1 x 1 00\nprobe One 2 y 1 00\nprobe DEFAULT 0 generic 1 00\n",
            "duplicate UDP probe name.*One",
        )
        self.assert_rejected(b"probe One 1 x 1 00\n", "missing DEFAULT UDP probe")
        self.assert_rejected(
            b"probe DEFAULT 1 generic 1 00\nprobe DEFAULT 0 generic 1 00\n",
            "port 0 is reserved for DEFAULT",
        )
        self.assert_rejected(b"unknown One 1 x 1 00\n", "malformed UDP probe")


class RuntimeOSImportTests(unittest.TestCase):
    def parse(self, value: bytes = OS_RUNTIME, address_family: str = "ipv4"):
        return parse_os_runtime(value, address_family, OS4_CONTEXT)

    def assert_rejected(self, value: bytes, message: str, address_family: str = "ipv4") -> None:
        with self.assertRaisesRegex(RuntimeCorpusError, message):
            self.parse(value, address_family)

    def test_imports_metadata_class_typed_operators_and_source_block_hash(self) -> None:
        records = self.parse()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.kind, "os_fingerprint")
        self.assertIsInstance(record.body, OSFingerprintSemantics)
        body = record.body
        self.assertEqual(body.runtime_id, "complete-stack-v4")
        self.assertEqual(body.name, "CompleteStack")
        self.assertEqual(body.vendor, "Example Vendor")
        self.assertEqual(body.os_family, "Example Family")
        self.assertEqual(body.os_generation, "1.0")
        self.assertEqual(body.device_type, "appliance")
        self.assertEqual(body.address_family, "ipv4")
        self.assertEqual(body.specificity, 20)
        self.assertEqual(
            {(signature.field, signature.operator, signature.value) for signature in body.signatures},
            {
                ("ttl", "eq", 64),
                ("window", "range", (1024, 4096)),
                ("mss", "eq", 1460),
                ("window_scale", "eq", 7),
                ("tcp_flags", "eq", 18),
                ("icmp_ttl", "eq", 64),
                ("icmp_type", "eq", 3),
                ("icmp_code", "eq", 3),
                ("udp_payload_length", "eq", 42),
                ("dont_fragment", "bool", True),
                ("sack_permitted", "bool", False),
                ("timestamps", "bool", True),
                ("tcp_options", "tcp_options", ("MSS", "WS", "SACK", "TS", "NOP")),
                ("udp_response_behavior", "text", "UDP_RESPONSE"),
                ("response_presence", "bool", False),
                ("ack_behavior", "text", "ACKNOWLEDGES_SYN"),
                ("sequence_behavior", "text", "INCREMENTAL"),
                ("response_behavior", "text", "SYN_ACK"),
            },
        )
        self.assertEqual(record.provenance[0].source_record_id, "data/os-fingerprints.db:fingerprint:complete-stack-v4")
        self.assertEqual(record.provenance[0].record_hash, OS_RUNTIME_HASH)

    def test_imports_ipv4_and_ipv6_metadata_from_current_first_party_runtime(self) -> None:
        ipv4 = parse_os_runtime((ROOT / "data" / "os-fingerprints.db").read_bytes(), "ipv4", OS4_CONTEXT)
        ipv6 = parse_os_runtime((ROOT / "data" / "os-fingerprints-v6.db").read_bytes(), "ipv6", OS6_CONTEXT)
        self.assertEqual(len(ipv4), 27)
        self.assertEqual(len(ipv6), 24)
        self.assertTrue(all(record.body.address_family == "ipv4" for record in ipv4))
        self.assertTrue(all(record.body.address_family == "ipv6" for record in ipv6))

    def test_rejects_duplicate_unknown_and_mixed_family_fields(self) -> None:
        self.assert_rejected(OS_RUNTIME.replace(b"TTL=64\n", b"TTL=64\nTTL_RANGE=1-64\n"), "duplicate OS signature field.*ttl")
        self.assert_rejected(OS_RUNTIME + b"UNSUPPORTED=1\n", "unknown OS directive.*UNSUPPORTED")
        self.assert_rejected(OS_RUNTIME.replace(b"ADDRESS_FAMILY=IPv4", b"ADDRESS_FAMILY=IPv6"), "mixed OS address family")
        self.assert_rejected(OS_RUNTIME, "address_family must be ipv4 or ipv6", "inet")

    def test_uses_lf_only_boundaries_and_lf_normalized_source_block_hashes(self) -> None:
        lf_records = self.parse()
        crlf_records = self.parse(OS_RUNTIME.replace(b"\n", b"\r\n"))
        self.assertEqual(crlf_records, lf_records)
        self.assertEqual(crlf_records[0].provenance[0].record_hash, OS_RUNTIME_HASH)
        for separator in (b"\r", b"\v", b"\f"):
            with self.subTest(separator=separator):
                self.assert_rejected(OS_RUNTIME.replace(b"\n", separator), "incomplete OS fingerprint")


if __name__ == "__main__":
    unittest.main()
