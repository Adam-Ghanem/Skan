from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.legacy_udp import (
    LegacyUDPError,
    compile_legacy_udp,
    load_legacy_udp,
    parse_legacy_udp,
    semantic_udp_ids,
    verify_udp_round_trip,
)
from tools.corpus.model import parse_record, stable_record_id
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
SOURCES = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")
LEGACY_UDP = ROOT / "data" / "udp-probes.db"


class LegacyUDPMigrationTests(unittest.TestCase):
    def test_migrates_repository_udp_corpus_with_stable_runtime_semantics(self) -> None:
        records = load_legacy_udp(LEGACY_UDP, SOURCES)

        self.assertEqual(len(records), 21)
        self.assertEqual(records[0].body.name, "DNS")  # type: ignore[union-attr]
        self.assertEqual(records[0].body.destination_port, 53)  # type: ignore[union-attr]
        self.assertEqual(records[-1].body.name, "DEFAULT")  # type: ignore[union-attr]
        self.assertEqual(records[-1].body.destination_port, 0)  # type: ignore[union-attr]
        self.assertEqual(
            tuple(record.body.declaration_order for record in records),  # type: ignore[union-attr]
            tuple(range(21)),
        )
        self.assertTrue(all(record.status == "imported" for record in records))
        self.assertTrue(
            all(
                record.provenance[0].source_revision
                == "git:399abe4821e9ce9138f53b0cb8a769d75329ba1f"
                for record in records
            )
        )

    def test_jsonl_and_runtime_compiler_round_trip_preserve_semantic_ids(self) -> None:
        migrated = load_legacy_udp(LEGACY_UDP, SOURCES)

        with tempfile.TemporaryDirectory() as directory:
            canonical_path = Path(directory) / "udp.jsonl"
            write_jsonl(canonical_path, migrated, SOURCES)
            reloaded = load_jsonl(
                canonical_path, SOURCES, expected_kind="udp_probe"
            )

        generated = compile_legacy_udp(reloaded, SOURCES)
        regenerated = parse_legacy_udp(generated, SOURCES)

        self.assertEqual(semantic_udp_ids(migrated), semantic_udp_ids(reloaded))
        verify_udp_round_trip(migrated, regenerated)
        self.assertEqual(generated, compile_legacy_udp(reloaded, SOURCES))

    def test_parser_normalizes_hex_without_changing_payload_semantics(self) -> None:
        text = "probe DNS 53 dns 512 AAbb\nprobe DEFAULT 0 generic 512 00\n"
        records = parse_legacy_udp(text, SOURCES)

        self.assertEqual(records[0].body.payload_hex, "aabb")  # type: ignore[union-attr]
        self.assertIn("probe DNS 53 dns 512 aabb\n", compile_legacy_udp(records, SOURCES))

    def test_rejects_runtime_conflicts_and_malformed_inputs(self) -> None:
        cases = (
            (
                "probe DNS 53 dns 512 00\nprobe DNS 54 dns 512 00\nprobe DEFAULT 0 generic 512 00\n",
                "duplicate probe name",
            ),
            (
                "probe DNS 53 dns 512 00\nprobe OTHER 53 other 512 00\nprobe DEFAULT 0 generic 512 00\n",
                "duplicate destination port",
            ),
            ("probe ZERO 0 generic 512 00\n", "port 0 is reserved for DEFAULT"),
            ("probe DNS 53 dns 512 00\n", "requires exactly one DEFAULT"),
            ("probe DEFAULT 0 generic 0 00\n", "max response must be in range"),
            (
                "probe DEFAULT 0 generic 1048577 00\n",
                "max response must be in range",
            ),
            ("probe DEFAULT 0 generic 512 0\n", "even-length hexadecimal"),
            ("probe DEFAULT 0 generic 512 gg\n", "even-length hexadecimal"),
            ("not-a-probe\n", "expected `probe NAME PORT HINT MAX_RESPONSE PAYLOAD_HEX`"),
        )
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(LegacyUDPError, message):
                    parse_legacy_udp(text, SOURCES)

    def test_rejects_payload_over_runtime_bound(self) -> None:
        oversized = "00" * 513
        text = f"probe DEFAULT 0 generic 512 {oversized}\n"
        with self.assertRaisesRegex(LegacyUDPError, "payload exceeds 512 bytes"):
            parse_legacy_udp(text, SOURCES)

    def test_compiler_rejects_cross_record_port_conflict(self) -> None:
        records = parse_legacy_udp(
            "probe ONE 1 one 512 00\n"
            "probe TWO 2 two 512 00\n"
            "probe DEFAULT 0 generic 512 00\n",
            SOURCES,
        )
        conflicting = copy.deepcopy(
            {
                "schema_version": records[1].schema_version,
                "id": records[1].id,
                "kind": records[1].kind,
                "body": {
                    "name": records[1].body.name,  # type: ignore[union-attr]
                    "destination_port": 1,
                    "protocol_hint": records[1].body.protocol_hint,  # type: ignore[union-attr]
                    "max_response_bytes": records[1].body.max_response_bytes,  # type: ignore[union-attr]
                    "payload_hex": records[1].body.payload_hex,  # type: ignore[union-attr]
                    "declaration_order": records[1].body.declaration_order,  # type: ignore[union-attr]
                },
                "provenance": [
                    {
                        "source_id": item.source_id,
                        "source_record_id": item.source_record_id,
                        "source_revision": item.source_revision,
                        "source_url": item.source_url,
                        "source_license": item.source_license,
                        "snapshot_hash": item.snapshot_hash,
                        "record_hash": item.record_hash,
                    }
                    for item in records[1].provenance
                ],
                "first_imported_revision": records[1].first_imported_revision,
                "last_verified_revision": records[1].last_verified_revision,
                "status": records[1].status,
                "notes": records[1].notes,
            }
        )
        conflicting["id"] = stable_record_id(conflicting)
        conflicting_record = parse_record(conflicting, SOURCES)

        with self.assertRaisesRegex(LegacyUDPError, "duplicate destination port: 1"):
            compile_legacy_udp(
                (records[0], conflicting_record, records[2]), SOURCES
            )

    def test_compiler_revalidates_record_identity(self) -> None:
        records = list(
            parse_legacy_udp(
                "probe DNS 53 dns 512 00\nprobe DEFAULT 0 generic 512 00\n",
                SOURCES,
            )
        )
        invalid_mapping = {
            "schema_version": records[0].schema_version,
            "id": records[0].id,
            "kind": records[0].kind,
            "body": {
                "name": records[0].body.name,  # type: ignore[union-attr]
                "destination_port": 54,
                "protocol_hint": records[0].body.protocol_hint,  # type: ignore[union-attr]
                "max_response_bytes": records[0].body.max_response_bytes,  # type: ignore[union-attr]
                "payload_hex": records[0].body.payload_hex,  # type: ignore[union-attr]
                "declaration_order": records[0].body.declaration_order,  # type: ignore[union-attr]
            },
            "provenance": [
                {
                    "source_id": item.source_id,
                    "source_record_id": item.source_record_id,
                    "source_revision": item.source_revision,
                    "source_url": item.source_url,
                    "source_license": item.source_license,
                    "snapshot_hash": item.snapshot_hash,
                    "record_hash": item.record_hash,
                }
                for item in records[0].provenance
            ],
            "first_imported_revision": records[0].first_imported_revision,
            "last_verified_revision": records[0].last_verified_revision,
            "status": records[0].status,
            "notes": records[0].notes,
        }
        from tools.corpus.model import CanonicalRecord, UDPProbeSemantics

        invalid_record = CanonicalRecord(
            schema_version=records[0].schema_version,
            id=records[0].id,
            kind="udp_probe",
            body=UDPProbeSemantics(**invalid_mapping["body"]),  # type: ignore[arg-type]
            provenance=records[0].provenance,
            first_imported_revision=records[0].first_imported_revision,
            last_verified_revision=records[0].last_verified_revision,
            status=records[0].status,
            notes=records[0].notes,
        )
        with self.assertRaisesRegex(LegacyUDPError, "id does not match semantic fingerprint"):
            compile_legacy_udp((invalid_record, records[1]), SOURCES)


if __name__ == "__main__":
    unittest.main()
