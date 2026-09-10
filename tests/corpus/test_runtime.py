from __future__ import annotations

from pathlib import Path
import unittest

from tools.corpus.model import ActiveProbeSemantics, ServiceMatcherSemantics
from tools.corpus.runtime import ImportContext, RuntimeCorpusError, parse_service_runtime
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
POLICY = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")[
    "skan-first-party"
]
CONTEXT = ImportContext(POLICY, "data/service-probes.db")


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


if __name__ == "__main__":
    unittest.main()
