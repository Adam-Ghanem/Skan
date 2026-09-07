import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.io import load_jsonl, record_to_dict, write_jsonl
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id
from tools.corpus.sources import load_source_manifest


SOURCES = load_source_manifest(Path("corpus/sources/sources.json"))


def make_record(pattern: str, product: str) -> CanonicalRecord:
    record = CanonicalRecord(
        id="",
        kind="service_matcher",
        transport="tcp",
        address_family="any",
        probe_id="Banner",
        probe_payload_ref=None,
        matcher_type="regex",
        matcher_expression=pattern,
        service="test-service",
        vendor="Skan",
        product=product,
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=("cpe:2.3:a:skan:test:*:*:*:*:*:*:*:*",),
        ports=(8080, 80, 8080),
        rarity=1,
        confidence=0.9,
        confidence_basis="fixture",
        evidence_requirements=("banner", "banner"),
        negative_constraints=(),
        provenance=(
            Provenance(
                source_id="skan-first-party",
                source_record_id=product,
                source_revision="repository",
                source_url="https://github.com/Adam-Ghanem/Skan",
                source_license="MIT",
                source_hash="sha256:" + "a" * 64,
            ),
        ),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="fixture",
    )
    return replace(record, id=stable_record_id(record))


class CanonicalJsonlTests(unittest.TestCase):
    def test_write_is_byte_deterministic_across_input_order(self):
        first = make_record("^A", "A")
        second = make_record("^B", "B")
        with tempfile.TemporaryDirectory() as temp:
            left = Path(temp) / "left.jsonl"
            right = Path(temp) / "right.jsonl"
            write_jsonl(left, [second, first])
            write_jsonl(right, [first, second])
            self.assertEqual(left.read_bytes(), right.read_bytes())
            self.assertTrue(left.read_bytes().endswith(b"\n"))

    def test_round_trip_sorts_records_and_normalizes_set_like_fields(self):
        first = make_record("^A", "A")
        second = make_record("^B", "B")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            write_jsonl(path, [second, first])
            loaded = load_jsonl(path, SOURCES)
            self.assertEqual([r.id for r in loaded], sorted([first.id, second.id]))
            serialized = record_to_dict(loaded[0])
            self.assertEqual(serialized["ports"], [80, 8080])
            self.assertEqual(serialized["evidence_requirements"], ["banner"])

    def test_rejects_duplicate_ids(self):
        record = make_record("^A", "A")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            write_jsonl(path, [record])
            payload = path.read_text(encoding="utf-8")
            path.write_text(payload + payload, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate canonical id"):
                load_jsonl(path, SOURCES)

    def test_rejects_tampered_serialized_id(self):
        record = make_record("^A", "A")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            write_jsonl(path, [record])
            payload = path.read_text(encoding="utf-8")
            payload = payload.replace(record.id, "skan-fp-v2-000000000000000000000000", 1)
            path.write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "id does not match"):
                load_jsonl(path, SOURCES)

    def test_empty_file_loads_as_empty_corpus(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "empty.jsonl"
            path.write_bytes(b"")
            self.assertEqual(load_jsonl(path, SOURCES), [])


if __name__ == "__main__":
    unittest.main()
