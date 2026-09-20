import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id, validate_record
from tools.corpus.sources import load_source_manifest


SOURCES = load_source_manifest(Path("corpus/sources/sources.json"))


def provenance() -> Provenance:
    return Provenance(
        source_id="skan-first-party",
        source_record_id="fixture",
        source_revision="repository",
        source_url="https://github.com/Adam-Ghanem/Skan",
        source_license="MIT",
        source_hash="sha256:" + "a" * 64,
    )


def base_record(kind: str = "active_probe") -> CanonicalRecord:
    return CanonicalRecord(
        id="",
        kind=kind,
        transport="tcp",
        address_family="any",
        probe_id="ProbeA",
        probe_payload_ref=None,
        matcher_type=None,
        matcher_expression=None,
        service=None,
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
        provenance=(provenance(),),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="fixture",
    )


class RuntimeFidelityModelTests(unittest.TestCase):
    def test_runtime_probe_fields_change_semantic_id(self):
        base = base_record()
        with_priority = replace(base, probe_priority=99)
        with_timeout = replace(base, probe_timeout_ms=2000)
        with_payload = replace(base, probe_payload_hex="00ff")
        with_fallback = replace(base, fallback_probe_ids=("Fallback",))

        ids = {
            stable_record_id(base),
            stable_record_id(with_priority),
            stable_record_id(with_timeout),
            stable_record_id(with_payload),
            stable_record_id(with_fallback),
        }
        self.assertEqual(len(ids), 5)

    def test_fallback_order_is_semantic(self):
        base = base_record()
        left = replace(base, fallback_probe_ids=("HTTPGet", "GenericBanner"))
        right = replace(base, fallback_probe_ids=("GenericBanner", "HTTPGet"))
        self.assertNotEqual(stable_record_id(left), stable_record_id(right))

    def test_match_runtime_fields_change_semantic_id(self):
        base = replace(
            base_record("service_matcher"),
            matcher_type="regex",
            matcher_expression="^HTTP/",
            service="http",
            match_strength="hard",
        )
        variants = (
            replace(base, match_strength="soft"),
            replace(base, extra_template="HTTP/$1"),
            replace(base, hostname_template="$1"),
            replace(base, tunnel_template="tls"),
        )
        for variant in variants:
            self.assertNotEqual(stable_record_id(base), stable_record_id(variant))

    def test_udp_runtime_fields_change_semantic_id(self):
        base = replace(
            base_record("udp_probe"),
            transport="udp",
            probe_payload_hex="00",
            protocol_hint="dns",
            max_response_bytes=512,
        )
        self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, protocol_hint="ntp")))
        self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, max_response_bytes=1024)))

    def test_os_feature_order_is_not_semantic(self):
        base = replace(
            base_record("os_fingerprint"),
            transport="none",
            address_family="ipv4",
            probe_id=None,
            ports=(),
            fingerprint_name="LinuxGeneric",
            os_family="Linux",
            os_features=(("TTL", "64"), ("DF", "Y")),
        )
        reordered = replace(base, os_features=(("DF", "Y"), ("TTL", "64")))
        self.assertEqual(stable_record_id(base), stable_record_id(reordered))

    def test_os_native_identity_fields_change_semantic_id(self):
        base = replace(
            base_record("os_fingerprint"),
            transport="none",
            address_family="ipv6",
            probe_id=None,
            ports=(),
            fingerprint_name="IPv6Linux",
            fingerprint_native_id="skan-v6-linux",
            specificity=13,
            os_family="Linux",
            os_features=(("TTL", "64"),),
        )
        self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, fingerprint_native_id="other")))
        self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, specificity=14)))

    def test_validation_rejects_invalid_runtime_fields(self):
        base = base_record()
        cases = (
            (replace(base, probe_payload_hex="0xz1"), "probe_payload_hex"),
            (replace(base, probe_payload_hex="abc"), "probe_payload_hex"),
            (replace(base, probe_priority=-1), "probe_priority"),
            (replace(base, probe_timeout_ms=0), "probe_timeout_ms"),
            (replace(base, fallback_probe_ids=("",)), "fallback_probe_ids"),
            (replace(base, fallback_probe_ids=("A", "A")), "fallback_probe_ids"),
            (replace(base, max_response_bytes=0), "max_response_bytes"),
            (replace(base, specificity=-1), "specificity"),
            (replace(base, os_features=(("TTL", "64"), ("TTL", "128"))), "os_features"),
        )
        for record, expected in cases:
            self.assertTrue(any(expected in error for error in validate_record(record, SOURCES)), (record, expected))

    def test_validation_rejects_invalid_match_strength(self):
        record = replace(
            base_record("service_matcher"),
            matcher_type="regex",
            matcher_expression="^HTTP/",
            service="http",
            match_strength="maybe",
        )
        self.assertTrue(any("match_strength" in error for error in validate_record(record, SOURCES)))

    def test_kind_specific_runtime_requirements_are_enforced(self):
        active_errors = validate_record(base_record("active_probe"), SOURCES)
        self.assertTrue(any("probe_payload_hex" in error for error in active_errors))
        self.assertTrue(any("probe_timeout_ms" in error for error in active_errors))

        matcher = replace(
            base_record("service_matcher"),
            matcher_type="regex",
            matcher_expression="^HTTP/",
            service="http",
        )
        self.assertTrue(any("match_strength" in error for error in validate_record(matcher, SOURCES)))

        udp = replace(base_record("udp_probe"), transport="udp")
        udp_errors = validate_record(udp, SOURCES)
        self.assertTrue(any("protocol_hint" in error for error in udp_errors))
        self.assertTrue(any("max_response_bytes" in error for error in udp_errors))
        self.assertTrue(any("probe_payload_hex" in error for error in udp_errors))

        os_record = replace(
            base_record("os_fingerprint"),
            transport="none",
            probe_id=None,
            ports=(),
            os_family="Linux",
        )
        os_errors = validate_record(os_record, SOURCES)
        self.assertTrue(any("fingerprint_name" in error for error in os_errors))
        self.assertTrue(any("os_features" in error for error in os_errors))


if __name__ == "__main__":
    unittest.main()
