import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.io import record_to_dict
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id
from tools.corpus.validate import validate_root


def source_policy(source_id: str = "source-a", expected_hash: str | None = None) -> dict:
    return {
        "id": source_id,
        "name": source_id,
        "homepage": "https://example.invalid",
        "source_url": "https://example.invalid/data",
        "license_spdx_or_policy": "MIT",
        "redistribution_allowed": True,
        "attribution_required": False,
        "approved_data_classes": ["service_matcher"],
        "blocked_data_classes": [],
        "pinned_revision": "rev-1",
        "expected_hash": expected_hash,
        "adapter": "fixture",
        "notes": "fixture source",
    }


def make_record(product: str, source_id: str = "source-a") -> CanonicalRecord:
    record = CanonicalRecord(
        id="",
        kind="service_matcher",
        transport="tcp",
        address_family="any",
        probe_id="GenericBanner",
        probe_payload_ref=None,
        matcher_type="regex",
        matcher_expression="^HELLO",
        service="hello",
        vendor="Example",
        product=product,
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(1234,),
        rarity=2,
        confidence=0.8,
        confidence_basis="fixture",
        evidence_requirements=("banner",),
        negative_constraints=(),
        provenance=(
            Provenance(
                source_id=source_id,
                source_record_id=product,
                source_revision="rev-1",
                source_url="https://example.invalid/data",
                source_license="MIT",
                source_hash="sha256:" + "a" * 64,
            ),
        ),
        first_imported_revision="rev-1",
        last_verified_revision="rev-1",
        status="imported",
        notes="",
    )
    return replace(record, id=stable_record_id(record))


class RepositoryValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "corpus/sources").mkdir(parents=True)
        (self.root / "corpus/canonical").mkdir(parents=True)
        (self.root / "corpus/overrides").mkdir(parents=True)
        self.write_sources([source_policy()])
        for name in ("services.jsonl", "os.jsonl", "udp.jsonl", "products.jsonl"):
            (self.root / "corpus/canonical" / name).write_bytes(b"")
        for name in ("aliases.json", "conflicts.json", "suppressions.json"):
            (self.root / "corpus/overrides" / name).write_text("{}\n", encoding="utf-8")

    def write_sources(self, sources: list[dict]) -> None:
        (self.root / "corpus/sources/sources.json").write_text(
            json.dumps({"schema_version": 1, "sources": sources}),
            encoding="utf-8",
        )

    def write_records(self, records: list[CanonicalRecord]) -> None:
        path = self.root / "corpus/canonical/services.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record_to_dict(record), sort_keys=True, separators=(",", ":")))
                handle.write("\n")

    def test_empty_foundation_validates_and_reports_zero_records(self):
        summary = validate_root(self.root)
        self.assertEqual(summary["total_records"], 0)
        self.assertEqual(summary["conflict_count"], 0)
        self.assertEqual(summary["records_by_kind"], {})
        self.assertEqual(summary["records_by_source"], {})

    def test_rejects_unknown_source_reference(self):
        self.write_records([make_record("Unknown", source_id="missing-source")])
        with self.assertRaisesRegex(ValueError, "unknown source_id"):
            validate_root(self.root)

    def test_rejects_source_data_class_not_approved(self):
        record = replace(
            make_record("Probe"),
            id="",
            kind="active_probe",
            matcher_type=None,
            matcher_expression=None,
            service=None,
        )
        record = replace(record, id=stable_record_id(record))
        self.write_records([record])
        with self.assertRaisesRegex(ValueError, "not approved for data class active_probe"):
            validate_root(self.root)

    def test_rejects_explicitly_blocked_data_class(self):
        policy = source_policy()
        policy["approved_data_classes"] = ["service_matcher", "active_probe"]
        policy["blocked_data_classes"] = ["active_probe"]
        self.write_sources([policy])
        record = replace(
            make_record("Probe"),
            id="",
            kind="active_probe",
            matcher_type=None,
            matcher_expression=None,
            service=None,
        )
        record = replace(record, id=stable_record_id(record))
        self.write_records([record])
        with self.assertRaisesRegex(ValueError, "blocked for data class active_probe"):
            validate_root(self.root)

    def test_rejects_malformed_override_json(self):
        (self.root / "corpus/overrides/aliases.json").write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "aliases.json"):
            validate_root(self.root)

    def test_rejects_unresolved_identity_conflict(self):
        left = make_record("ProductA")
        right = make_record("ProductB")
        self.write_records([left, right])
        with self.assertRaisesRegex(ValueError, "unresolved corpus conflict"):
            validate_root(self.root)

    def test_accepts_explicit_conflict_resolution(self):
        left = make_record("ProductA")
        right = make_record("ProductB")
        self.write_records([left, right])
        pair = "|".join(sorted((left.id, right.id)))
        (self.root / "corpus/overrides/conflicts.json").write_text(
            json.dumps({pair: {"resolution": "keep both; fixture proves ambiguity"}}) + "\n",
            encoding="utf-8",
        )
        summary = validate_root(self.root)
        self.assertEqual(summary["total_records"], 2)
        self.assertEqual(summary["conflict_count"], 1)

    def test_rejects_snapshot_hash_mismatch(self):
        expected = "sha256:" + "0" * 64
        self.write_sources([source_policy(expected_hash=expected)])
        snapshot = self.root / "corpus/snapshots/source-a/source"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(b"not-the-pinned-content")
        with self.assertRaisesRegex(ValueError, "snapshot hash mismatch"):
            validate_root(self.root)

    def test_rejects_missing_snapshot_for_pinned_hash(self):
        expected = "sha256:" + "0" * 64
        self.write_sources([source_policy(expected_hash=expected)])
        with self.assertRaisesRegex(ValueError, "missing pinned snapshot"):
            validate_root(self.root)

    def test_rejects_non_object_override_root(self):
        (self.root / "corpus/overrides/suppressions.json").write_text("[]\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "suppressions.json.*object"):
            validate_root(self.root)


if __name__ == "__main__":
    unittest.main()
