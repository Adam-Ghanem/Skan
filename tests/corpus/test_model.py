import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id, validate_record
from tools.corpus.sources import load_source_manifest


SOURCES = load_source_manifest(Path("corpus/sources/sources.json"))


def make_record(
    source_id: str = "skan-first-party",
    source_record_id: str = "ssh-openssh",
    pattern: str | None = "^SSH-",
) -> CanonicalRecord:
    return CanonicalRecord(
        id="",
        kind="service_matcher",
        transport="tcp",
        address_family="any",
        probe_id="SSHBanner",
        probe_payload_ref=None,
        matcher_type="regex",
        matcher_expression=pattern,
        service="ssh",
        vendor=None,
        product="OpenSSH",
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(22,),
        rarity=1,
        confidence=0.98,
        confidence_basis="specific banner regex",
        evidence_requirements=("banner",),
        negative_constraints=(),
        provenance=(
            Provenance(
                source_id=source_id,
                source_record_id=source_record_id,
                source_revision="repository",
                source_url="https://github.com/Adam-Ghanem/Skan",
                source_license="MIT",
                source_hash="sha256:" + "1" * 64,
            ),
        ),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="",
    )


class CanonicalRecordTests(unittest.TestCase):
    def test_stable_id_ignores_provenance_identity(self):
        left = make_record(source_record_id="left")
        right_provenance = replace(
            make_record(source_record_id="right").provenance[0],
            source_hash="sha256:" + "2" * 64,
        )
        right = replace(make_record(source_record_id="right"), provenance=(right_provenance,))
        self.assertEqual(stable_record_id(left), stable_record_id(right))

    def test_stable_id_changes_when_matcher_semantics_change(self):
        left = make_record(pattern="^SSH-")
        right = make_record(pattern="^HTTP/")
        self.assertNotEqual(stable_record_id(left), stable_record_id(right))

    def test_stable_id_has_public_prefix_and_fixed_length(self):
        value = stable_record_id(make_record())
        self.assertTrue(value.startswith("skan-fp-v2-"))
        self.assertEqual(len(value), len("skan-fp-v2-") + 24)

    def test_rejects_unknown_provenance_source(self):
        errors = validate_record(make_record(source_id="unknown-source"), SOURCES)
        self.assertTrue(any("unknown source_id" in error for error in errors))

    def test_rejects_missing_provenance(self):
        errors = validate_record(replace(make_record(), provenance=()), SOURCES)
        self.assertTrue(any("provenance" in error for error in errors))

    def test_rejects_unsupported_status(self):
        errors = validate_record(replace(make_record(), status="maybe"), SOURCES)
        self.assertTrue(any("status" in error for error in errors))

    def test_rejects_confidence_outside_unit_interval(self):
        errors = validate_record(replace(make_record(), confidence=1.01), SOURCES)
        self.assertTrue(any("confidence" in error for error in errors))

    def test_service_matcher_requires_expression(self):
        errors = validate_record(make_record(pattern=None), SOURCES)
        self.assertTrue(any("matcher_expression" in error for error in errors))

    def test_rejects_out_of_range_port(self):
        errors = validate_record(replace(make_record(), ports=(70000,)), SOURCES)
        self.assertTrue(any("ports" in error for error in errors))

    def test_rejects_serialized_id_that_does_not_match_semantics(self):
        record = replace(make_record(), id="skan-fp-v2-000000000000000000000000")
        errors = validate_record(record, SOURCES)
        self.assertTrue(any("id does not match" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
