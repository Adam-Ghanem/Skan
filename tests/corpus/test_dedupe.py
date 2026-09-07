import unittest
from dataclasses import replace

from tools.corpus.dedupe import merge_records
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id


def provenance(source_id: str, record_id: str, hash_char: str) -> Provenance:
    return Provenance(
        source_id=source_id,
        source_record_id=record_id,
        source_revision="rev-1",
        source_url=f"https://example.invalid/{source_id}",
        source_license="MIT",
        source_hash="sha256:" + hash_char * 64,
    )


def make_record(
    *,
    product: str,
    status: str = "imported",
    confidence: float = 0.70,
    source_id: str = "source-a",
    source_record_id: str = "record-a",
    hash_char: str = "a",
) -> CanonicalRecord:
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
        confidence=confidence,
        confidence_basis="fixture",
        evidence_requirements=("banner",),
        negative_constraints=(),
        provenance=(provenance(source_id, source_record_id, hash_char),),
        first_imported_revision="rev-1",
        last_verified_revision="rev-1",
        status=status,
        notes="",
    )
    return replace(record, id=stable_record_id(record))


class DedupeTests(unittest.TestCase):
    def test_same_semantic_id_merges_all_provenance(self):
        left = make_record(product="Same", source_id="source-a", source_record_id="a", hash_char="a")
        right = make_record(product="Same", source_id="source-b", source_record_id="b", hash_char="b")

        merged, conflicts = merge_records([right, left])

        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].provenance), 2)
        self.assertEqual(
            [item.source_id for item in merged[0].provenance],
            ["source-a", "source-b"],
        )
        self.assertEqual(conflicts, [])

    def test_same_evidence_with_different_identity_emits_conflict(self):
        left = make_record(product="ProductA")
        right = make_record(product="ProductB", source_id="source-b", source_record_id="b", hash_char="b")

        merged, conflicts = merge_records([right, left])

        self.assertEqual(len(merged), 2)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].differing_fields, ("product",))
        self.assertEqual(
            (conflicts[0].left_id, conflicts[0].right_id),
            tuple(sorted((left.id, right.id))),
        )

    def test_exact_merge_uses_deterministic_best_metadata(self):
        imported = make_record(
            product="Same",
            status="imported",
            confidence=0.70,
            source_id="source-b",
            source_record_id="b",
            hash_char="b",
        )
        verified = make_record(
            product="Same",
            status="verified",
            confidence=0.95,
            source_id="source-a",
            source_record_id="a",
            hash_char="a",
        )
        verified = replace(verified, confidence_basis="verified fixture")

        merged, conflicts = merge_records([imported, verified])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].status, "verified")
        self.assertEqual(merged[0].confidence, 0.95)
        self.assertEqual(merged[0].confidence_basis, "fixture; verified fixture")
        self.assertEqual(conflicts, [])

    def test_output_order_is_deterministic(self):
        left = make_record(product="A")
        right = make_record(product="B", source_id="source-b", source_record_id="b", hash_char="b")
        merged, conflicts = merge_records([right, left])
        self.assertEqual([record.id for record in merged], sorted([left.id, right.id]))
        self.assertEqual(
            [(conflict.left_id, conflict.right_id) for conflict in conflicts],
            sorted((conflict.left_id, conflict.right_id) for conflict in conflicts),
        )


if __name__ == "__main__":
    unittest.main()
