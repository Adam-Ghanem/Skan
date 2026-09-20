import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id, validate_record
from tools.corpus.sources import load_source_manifest


SOURCES = load_source_manifest(Path("corpus/sources/sources.json"))


def base_record(kind: str) -> CanonicalRecord:
    record = CanonicalRecord(
        id="",
        kind=kind,
        transport="tcp",
        address_family="any",
        probe_id="ProbeA",
        probe_payload_ref=None,
        matcher_type="regex" if kind == "service_matcher" else None,
        matcher_expression="^A" if kind == "service_matcher" else None,
        service="a" if kind == "service_matcher" else None,
        vendor="Skan",
        product=None,
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(80,),
        rarity=1,
        confidence=0.9,
        confidence_basis="fixture",
        evidence_requirements=("response",),
        negative_constraints=(),
        provenance=(Provenance(
            source_id="skan-first-party",
            source_record_id=kind,
            source_revision="repository",
            source_url="https://github.com/Adam-Ghanem/Skan",
            source_license="MIT",
            source_hash="sha256:" + "c" * 64,
        ),),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="",
        probe_payload_hex="00" if kind == "active_probe" else None,
        probe_timeout_ms=1000 if kind == "active_probe" else None,
        match_strength="hard" if kind == "service_matcher" else None,
    )
    return replace(record, id=stable_record_id(record))


class RuntimeOrderFidelityTests(unittest.TestCase):
    def test_probe_declaration_order_is_runtime_semantic(self):
        base = base_record("active_probe")
        first = replace(base, id="", probe_order=0)
        second = replace(base, id="", probe_order=1)
        self.assertNotEqual(stable_record_id(first), stable_record_id(second))

    def test_rule_declaration_order_is_runtime_semantic(self):
        base = base_record("service_matcher")
        first = replace(base, id="", rule_order=0)
        second = replace(base, id="", rule_order=1)
        self.assertNotEqual(stable_record_id(first), stable_record_id(second))

    def test_order_fields_reject_negative_or_non_integer_values(self):
        base = base_record("active_probe")
        for field, value in (("probe_order", -1), ("probe_order", "1"), ("rule_order", -1), ("rule_order", 1.0)):
            record = replace(base, id="", **{field: value})
            errors = validate_record(record, SOURCES)
            self.assertTrue(any(field in error for error in errors), (field, value, errors))


if __name__ == "__main__":
    unittest.main()
