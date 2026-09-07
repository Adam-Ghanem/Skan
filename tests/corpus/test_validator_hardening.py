import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.io import record_to_dict
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id
from tools.corpus.validate import validate_root


def make_source(*, redistribution_allowed: bool = True) -> dict:
    return {
        "id": "source-a",
        "name": "source-a",
        "homepage": "https://example.invalid",
        "source_url": "https://example.invalid/data",
        "license_spdx_or_policy": "MIT",
        "redistribution_allowed": redistribution_allowed,
        "attribution_required": False,
        "approved_data_classes": ["service_matcher"],
        "blocked_data_classes": [],
        "pinned_revision": "rev-1",
        "expected_hash": None,
        "adapter": "fixture",
        "notes": "fixture source",
    }


def make_record() -> CanonicalRecord:
    record = CanonicalRecord(
        id="",
        kind="service_matcher",
        transport="tcp",
        address_family="any",
        probe_id="Banner",
        probe_payload_ref=None,
        matcher_type="regex",
        matcher_expression="^HELLO",
        service="hello",
        vendor="Example",
        product="Product",
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(1234,),
        rarity=1,
        confidence=0.9,
        confidence_basis="fixture",
        evidence_requirements=("banner",),
        negative_constraints=(),
        provenance=(Provenance(
            source_id="source-a",
            source_record_id="record-a",
            source_revision="rev-1",
            source_url="https://example.invalid/data",
            source_license="MIT",
            source_hash="sha256:" + "a" * 64,
        ),),
        first_imported_revision="rev-1",
        last_verified_revision="rev-1",
        status="imported",
        notes="",
    )
    return replace(record, id=stable_record_id(record))


class ValidatorHardeningTests(unittest.TestCase):
    def make_root(self, *, redistribution_allowed: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "corpus/sources").mkdir(parents=True)
        (root / "corpus/canonical").mkdir(parents=True)
        (root / "corpus/overrides").mkdir(parents=True)
        (root / "corpus/sources/sources.json").write_text(
            json.dumps({"schema_version": 1, "sources": [make_source(redistribution_allowed=redistribution_allowed)]}),
            encoding="utf-8",
        )
        for name in ("services.jsonl", "os.jsonl", "udp.jsonl", "products.jsonl"):
            (root / "corpus/canonical" / name).write_bytes(b"")
        for name in ("aliases.json", "conflicts.json", "suppressions.json"):
            (root / "corpus/overrides" / name).write_text("{}\n", encoding="utf-8")
        return root

    @staticmethod
    def write_record(path: Path, record: CanonicalRecord) -> None:
        path.write_text(
            json.dumps(record_to_dict(record), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_rejects_same_canonical_id_across_different_files(self):
        root = self.make_root()
        record = make_record()
        self.write_record(root / "corpus/canonical/services.jsonl", record)
        self.write_record(root / "corpus/canonical/products.jsonl", record)
        with self.assertRaisesRegex(ValueError, "duplicate canonical id across corpus files"):
            validate_root(root)

    def test_rejects_record_from_non_redistributable_source(self):
        root = self.make_root(redistribution_allowed=False)
        self.write_record(root / "corpus/canonical/services.jsonl", make_record())
        with self.assertRaisesRegex(ValueError, "does not allow redistribution"):
            validate_root(root)


if __name__ == "__main__":
    unittest.main()
