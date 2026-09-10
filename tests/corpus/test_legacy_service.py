from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.legacy_service import (
    LegacyServiceError,
    compile_legacy_service,
    load_legacy_service,
    parse_legacy_service,
    semantic_service_ids,
    verify_service_round_trip,
)
from tools.corpus.model import ServiceMatcherSemantics, stable_record_id
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
SOURCES = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")
LEGACY_SERVICE = ROOT / "data" / "service-probes.db"


SYNTHETIC = r'''# comment
Probe TCP Demo rarity=2 priority=90 timeout=750 ports=80,8080 fallback=Generic
send "GET /\r\n\x00"
softmatch type=regex pattern="^Demo/\x00([0-9.]+)" service=demo product="Demo Server" version="$1" extra="proto #1" hostname=demo.local tunnel=tls confidence=0.75
match type=exact pattern="\x00A" service=binary confidence=0.9
Probe TCP Generic rarity=3
send "\r\n"
match pattern=ready service=text product=Text confidence=0.45
'''


class LegacyServiceMigrationTests(unittest.TestCase):
    def test_parses_active_probes_and_rules_with_byte_exact_semantics(self) -> None:
        records = parse_legacy_service(SYNTHETIC, SOURCES)
        active = [record for record in records if record.kind == "active_probe"]
        matchers = [record for record in records if record.kind == "service_matcher"]

        self.assertEqual(len(active), 2)
        self.assertEqual(len(matchers), 3)
        self.assertEqual(active[0].body.probe_name, "Demo")  # type: ignore[union-attr]
        self.assertEqual(active[0].body.transport, "tcp")  # type: ignore[union-attr]
        self.assertEqual(active[0].body.payload_hex, "474554202f0d0a00")  # type: ignore[union-attr]
        self.assertEqual(active[0].body.rarity, 2)  # type: ignore[union-attr]
        self.assertEqual(active[0].body.priority, 90)  # type: ignore[union-attr]
        self.assertEqual(active[0].body.timeout_ms, 750)  # type: ignore[union-attr]
        self.assertEqual(active[0].body.ports, (80, 8080))  # type: ignore[union-attr]
        self.assertEqual(active[0].body.fallback_probe_names, ("Generic",))  # type: ignore[union-attr]

        self.assertEqual(matchers[0].body.matcher_type, "regex")  # type: ignore[union-attr]
        self.assertEqual(
            matchers[0].body.pattern_hex,  # type: ignore[union-attr]
            "5e44656d6f2f00285b302d392e5d2b29",
        )
        self.assertEqual(matchers[0].body.strength, "soft")  # type: ignore[union-attr]
        self.assertEqual(matchers[0].body.product, "Demo Server")  # type: ignore[union-attr]
        self.assertEqual(matchers[0].body.extra, "proto #1")  # type: ignore[union-attr]
        self.assertEqual(matchers[0].body.rule_order, 0)  # type: ignore[union-attr]
        self.assertEqual(matchers[1].body.pattern_hex, "0041")  # type: ignore[union-attr]
        self.assertEqual(matchers[2].body.matcher_type, "prefix")  # type: ignore[union-attr]

    def test_round_trip_through_jsonl_and_generated_runtime_is_semantically_stable(self) -> None:
        expected = parse_legacy_service(SYNTHETIC, SOURCES)
        generated = compile_legacy_service(expected, SOURCES)
        actual = parse_legacy_service(generated, SOURCES)
        verify_service_round_trip(expected, actual)
        self.assertEqual(semantic_service_ids(expected), semantic_service_ids(actual))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.jsonl"
            write_jsonl(path, expected, SOURCES)
            reloaded = load_jsonl(path, SOURCES)
            self.assertEqual(
                sorted(record.id for record in expected),
                sorted(record.id for record in reloaded),
            )

    def test_repository_service_corpus_migrates_and_recompiles_without_semantic_drift(self) -> None:
        expected = load_legacy_service(LEGACY_SERVICE, SOURCES)
        active = [record for record in expected if record.kind == "active_probe"]
        matchers = [record for record in expected if record.kind == "service_matcher"]

        self.assertGreaterEqual(len(active), 12)
        self.assertGreaterEqual(len(matchers), 40)
        self.assertEqual(active[0].body.probe_name, "HTTPGet")  # type: ignore[union-attr]
        self.assertTrue(any(record.body.probe_name == "TLSClientHello" for record in active))  # type: ignore[union-attr]
        self.assertTrue(any(record.body.service == "ssh" for record in matchers))  # type: ignore[union-attr]
        self.assertTrue(all(record.status == "imported" for record in expected))

        generated = compile_legacy_service(expected, SOURCES)
        actual = parse_legacy_service(generated, SOURCES)
        verify_service_round_trip(expected, actual)
        self.assertEqual(generated, compile_legacy_service(actual, SOURCES))

    def test_rejects_missing_cross_probe_fallback(self) -> None:
        text = 'Probe TCP Demo fallback=Missing\nsend "x"\n'
        with self.assertRaisesRegex(LegacyServiceError, "unknown fallback"):
            parse_legacy_service(text, SOURCES)

    def test_rejects_cross_transport_fallback(self) -> None:
        text = (
            'Probe TCP Demo fallback=Other\nsend "x"\n'
            'Probe UDP Other\nsend "x"\n'
        )
        with self.assertRaisesRegex(LegacyServiceError, "transport"):
            parse_legacy_service(text, SOURCES)

    def test_rejects_duplicate_probe_names_and_ambiguous_send_lines(self) -> None:
        duplicate = 'Probe TCP Demo\nProbe TCP Demo\n'
        with self.assertRaisesRegex(LegacyServiceError, "duplicate probe name"):
            parse_legacy_service(duplicate, SOURCES)

        duplicate_send = 'Probe TCP Demo\nsend "a"\nsend "b"\n'
        with self.assertRaisesRegex(LegacyServiceError, "duplicate send"):
            parse_legacy_service(duplicate_send, SOURCES)

    def test_rejects_runtime_rule_without_required_evidence_fields(self) -> None:
        missing_confidence = (
            'Probe TCP Demo\nsend "x"\n'
            'match type=prefix pattern=x service=test\n'
        )
        with self.assertRaisesRegex(LegacyServiceError, "confidence"):
            parse_legacy_service(missing_confidence, SOURCES)

    def test_compiler_rejects_unrepresentable_cpe_metadata(self) -> None:
        records = list(parse_legacy_service(SYNTHETIC, SOURCES))
        matcher = next(record for record in records if record.kind == "service_matcher")
        assert isinstance(matcher.body, ServiceMatcherSemantics)
        changed_body = replace(matcher.body, cpe=("cpe:/a:example:test",))
        changed = replace(matcher, body=changed_body)
        changed = replace(changed, id=stable_record_id(changed))
        records[records.index(matcher)] = changed

        with self.assertRaisesRegex(LegacyServiceError, "CPE"):
            compile_legacy_service(records, SOURCES)


if __name__ == "__main__":
    unittest.main()
