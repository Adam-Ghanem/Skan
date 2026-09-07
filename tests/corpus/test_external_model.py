from __future__ import annotations

import unittest

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id, validate_record
from tools.corpus.sources import SourcePolicy


SOURCE = SourcePolicy(
    id="fixture-source",
    name="Fixture",
    homepage="https://example.invalid",
    source_url="https://example.invalid/data",
    license_spdx_or_policy="CC0-1.0",
    redistribution_allowed=True,
    attribution_required=False,
    approved_data_classes=(
        "web_fingerprint",
        "device_fingerprint",
        "port_registry",
        "product_record",
        "product_alias",
        "cpe_record",
    ),
    blocked_data_classes=(),
    pinned_revision="r1",
    expected_hash=None,
    adapter="fixture",
    notes="",
)
SOURCES = {SOURCE.id: SOURCE}
PROVENANCE = (
    Provenance(
        source_id=SOURCE.id,
        source_record_id="1",
        source_revision="r1",
        source_url=SOURCE.source_url,
        source_license=SOURCE.license_spdx_or_policy,
        source_hash="sha256:" + "a" * 64,
    ),
)


def make_record(kind: str, **changes: object) -> CanonicalRecord:
    values: dict[str, object] = dict(
        id="",
        kind=kind,
        transport="none",
        address_family="none",
        probe_id=None,
        probe_payload_ref=None,
        matcher_type=None,
        matcher_expression=None,
        service=None,
        vendor="Example",
        product="Widget",
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(),
        rarity=None,
        confidence=None,
        confidence_basis="metadata",
        evidence_requirements=(),
        negative_constraints=(),
        provenance=PROVENANCE,
        first_imported_revision="r1",
        last_verified_revision="r1",
        status="imported",
        notes="",
    )
    values.update(changes)
    record = CanonicalRecord(**values)  # type: ignore[arg-type]
    return CanonicalRecord(**{**record.__dict__, "id": stable_record_id(record)})


class ExternalCanonicalModelTests(unittest.TestCase):
    def test_external_kinds_are_supported(self) -> None:
        for kind in (
            "web_fingerprint",
            "device_fingerprint",
            "port_registry",
            "product_record",
            "product_alias",
            "cpe_record",
        ):
            record = make_record(kind)
            self.assertNotIn(f"unsupported kind: {kind}", validate_record(record, SOURCES))

    def test_metadata_records_cannot_claim_detection_confidence(self) -> None:
        for kind in ("port_registry", "product_record", "product_alias", "cpe_record"):
            record = make_record(kind, confidence=0.9, confidence_basis="strong")
            errors = validate_record(record, SOURCES)
            self.assertTrue(any("metadata" in error and "confidence" in error for error in errors), errors)

    def test_web_fingerprint_requires_evidence_dimension(self) -> None:
        record = make_record(
            "web_fingerprint",
            transport="tcp",
            matcher_type="regex",
            matcher_expression="nginx",
            service="http",
            confidence=0.6,
            confidence_basis="medium",
        )
        errors = validate_record(record, SOURCES)
        self.assertTrue(any("evidence_requirements" in error for error in errors), errors)

    def test_semantic_id_is_source_independent(self) -> None:
        left = make_record("product_record")
        other_provenance = (
            Provenance(
                source_id=SOURCE.id,
                source_record_id="2",
                source_revision="r2",
                source_url=SOURCE.source_url,
                source_license=SOURCE.license_spdx_or_policy,
                source_hash="sha256:" + "b" * 64,
            ),
        )
        right = CanonicalRecord(**{**left.__dict__, "id": "", "provenance": other_provenance})
        self.assertEqual(left.id, stable_record_id(right))


if __name__ == "__main__":
    unittest.main()
