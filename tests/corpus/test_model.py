from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import unittest

from tools.corpus.model import (
    ActiveProbeSemantics,
    CanonicalRecordError,
    OSFingerprintSemantics,
    UDPProbeSemantics,
    parse_record,
    runtime_regex_is_valid,
    stable_record_id,
)
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
SOURCES = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")
REVISION = "git:399abe4821e9ce9138f53b0cb8a769d75329ba1f"
SOURCE_URL = (
    "https://github.com/Adam-Ghanem/Skan/tree/"
    "399abe4821e9ce9138f53b0cb8a769d75329ba1f/data"
)
RECORD_HASH = "sha256:" + ("1" * 64)


def valid_service_record() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 2,
        "id": "",
        "kind": "service_matcher",
        "body": {
            "probe_name": "HTTPGet",
            "matcher_type": "regex",
            "pattern": "^HTTP/[0-9.]+.*Server: Apache/([0-9.]+)",
            "pattern_hex": None,
            "strength": "hard",
            "service": "http",
            "product": "Apache-httpd",
            "version_template": "$1",
            "extra": None,
            "hostname_template": None,
            "tunnel": None,
            "confidence": 0.99,
            "rule_order": 0,
            "cpe": ["cpe:/a:apache:http_server"],
        },
        "provenance": [
            {
                "source_id": "skan-first-party",
                "source_record_id": "service:HTTPGet:apache",
                "source_revision": REVISION,
                "source_url": SOURCE_URL,
                "source_license": "MIT",
                "snapshot_hash": None,
                "record_hash": RECORD_HASH,
            }
        ],
        "first_imported_revision": REVISION,
        "last_verified_revision": REVISION,
        "status": "verified",
        "notes": "Synthetic unit-test record.",
    }
    value["id"] = stable_record_id(value)
    return value


def valid_os_record() -> dict[str, object]:
    value = valid_service_record()
    value["kind"] = "os_fingerprint"
    value["body"] = {
        "runtime_id": "skan-v4-linux-synthetic",
        "name": "Synthetic Linux style",
        "vendor": "Linux",
        "os_family": "Linux",
        "os_generation": "modern",
        "device_type": "general-purpose",
        "address_family": "ipv4",
        "specificity": 18,
        "signatures": [
            {
                "field": "ttl",
                "operator": "range",
                "value": [45, 64],
            }
        ],
    }
    value["provenance"][0]["source_record_id"] = "os:synthetic-linux"  # type: ignore[index]
    value["id"] = stable_record_id(value)
    return value


def valid_active_probe_record() -> dict[str, object]:
    value = valid_service_record()
    value["kind"] = "active_probe"
    value["body"] = {
        "probe_name": "SSHBanner",
        "transport": "tcp",
        "payload_hex": "0d0a",
        "rarity": 1,
        "priority": 100,
        "timeout_ms": 1400,
        "ports": [22],
        "fallback_probe_names": ["GenericBanner"],
        "declaration_order": 1,
    }
    value["provenance"][0]["source_record_id"] = "probe:SSHBanner"  # type: ignore[index]
    value["id"] = stable_record_id(value)
    return value


def valid_udp_probe_record() -> dict[str, object]:
    value = valid_service_record()
    value["kind"] = "udp_probe"
    value["body"] = {
        "name": "DNS",
        "destination_port": 53,
        "protocol_hint": "dns",
        "max_response_bytes": 4096,
        "payload_hex": "00",
        "declaration_order": 0,
    }
    value["provenance"][0]["source_record_id"] = "udp:DNS"  # type: ignore[index]
    value["id"] = stable_record_id(value)
    return value


class CanonicalRecordTests(unittest.TestCase):
    def assert_rejected(self, value: dict[str, object], message: str) -> None:
        with self.assertRaisesRegex(CanonicalRecordError, message):
            parse_record(value, SOURCES)

    def test_parses_immutable_schema_v2_record(self) -> None:
        record = parse_record(valid_service_record(), SOURCES)
        self.assertEqual(record.schema_version, 2)
        self.assertEqual(record.kind, "service_matcher")
        self.assertEqual(record.id, stable_record_id(record))
        with self.assertRaises(FrozenInstanceError):
            record.notes = "changed"  # type: ignore[misc]

    def test_parses_all_four_runtime_record_kinds(self) -> None:
        active = parse_record(valid_active_probe_record(), SOURCES)
        udp = parse_record(valid_udp_probe_record(), SOURCES)
        os_record = parse_record(valid_os_record(), SOURCES)
        self.assertIsInstance(active.body, ActiveProbeSemantics)
        self.assertIsInstance(udp.body, UDPProbeSemantics)
        self.assertIsInstance(os_record.body, OSFingerprintSemantics)

    def test_rejects_unknown_fields_and_incompatible_schema(self) -> None:
        value = valid_service_record()
        value["download_command"] = "run-me"
        self.assert_rejected(value, "unknown fields: download_command")

        value = valid_service_record()
        value["schema_version"] = 1
        self.assert_rejected(value, "schema_version must be 2")

        value = valid_service_record()
        value["schema_version"] = True
        self.assert_rejected(value, "schema_version must be 2")

        value = valid_service_record()
        value["body"]["surprise"] = True  # type: ignore[index]
        self.assert_rejected(value, "service_matcher body: unknown fields: surprise")

    def test_requires_exact_stable_identifier(self) -> None:
        value = valid_service_record()
        value["id"] = ""
        self.assert_rejected(value, "id is required")

        value["id"] = "skan-db-v2-" + ("0" * 64)
        self.assert_rejected(value, "id does not match semantic fingerprint")

    def test_id_covers_runtime_semantics_but_not_governance(self) -> None:
        original = valid_service_record()
        governance_change = copy.deepcopy(original)
        governance_change["notes"] = "Different review note."
        governance_change["provenance"][0]["record_hash"] = "sha256:" + ("2" * 64)  # type: ignore[index]
        self.assertEqual(stable_record_id(original), stable_record_id(governance_change))

        expression_change = copy.deepcopy(original)
        expression_change["body"]["pattern"] = "^SSH-"  # type: ignore[index]
        self.assertNotEqual(stable_record_id(original), stable_record_id(expression_change))

        confidence_change = copy.deepcopy(original)
        confidence_change["body"]["confidence"] = 0.75  # type: ignore[index]
        self.assertNotEqual(stable_record_id(original), stable_record_id(confidence_change))

        reordered_mapping = dict(reversed(tuple(original.items())))
        reordered_mapping["body"] = dict(
            reversed(tuple(original["body"].items()))  # type: ignore[union-attr]
        )
        self.assertEqual(stable_record_id(original), stable_record_id(reordered_mapping))

        active = valid_active_probe_record()
        active["body"]["ports"] = [22, 80]  # type: ignore[index]
        reversed_ports = copy.deepcopy(active)
        reversed_ports["body"]["ports"] = [80, 22]  # type: ignore[index]
        self.assertEqual(stable_record_id(active), stable_record_id(reversed_ports))

        os_record = valid_os_record()
        os_record["body"]["signatures"].append(  # type: ignore[index,union-attr]
            {"field": "window", "operator": "eq", "value": 64240}
        )
        reversed_signatures = copy.deepcopy(os_record)
        reversed_signatures["body"]["signatures"].reverse()  # type: ignore[index,union-attr]
        self.assertEqual(
            stable_record_id(os_record),
            stable_record_id(reversed_signatures),
        )

    def test_binds_provenance_to_manifest_policy(self) -> None:
        cases = (
            ("source_revision", "git:" + ("0" * 40), "source_revision does not match"),
            ("source_url", "https://example.invalid/data", "source_url does not match"),
            ("source_license", "Apache-2.0", "source_license does not match"),
            ("record_hash", "sha256:bad", "record_hash must be sha256"),
        )
        for field, replacement, message in cases:
            with self.subTest(field=field):
                value = valid_service_record()
                value["provenance"][0][field] = replacement  # type: ignore[index]
                self.assert_rejected(value, message)

        value = valid_service_record()
        value["provenance"][0]["source_id"] = "unknown"  # type: ignore[index]
        self.assert_rejected(value, "unknown source_id")

        value = valid_service_record()
        value["provenance"][0]["unexpected"] = True  # type: ignore[index]
        self.assert_rejected(value, r"provenance\[0\]: unknown fields: unexpected")

        restricted = {
            "skan-first-party": replace(
                SOURCES["skan-first-party"],
                approved_data_classes=("active_probe",),
            )
        }
        with self.assertRaisesRegex(CanonicalRecordError, "not authorized for kind"):
            parse_record(valid_service_record(), restricted)

        non_redistributable = {
            "skan-first-party": replace(
                SOURCES["skan-first-party"],
                redistribution_allowed=False,
            )
        }
        with self.assertRaisesRegex(CanonicalRecordError, "does not permit redistribution"):
            parse_record(valid_service_record(), non_redistributable)

        snapshot_hash = "sha256:" + ("a" * 64)
        snapshot_bound = {
            "skan-first-party": replace(
                SOURCES["skan-first-party"],
                expected_hash=snapshot_hash,
            )
        }
        with self.assertRaisesRegex(CanonicalRecordError, "snapshot_hash does not match"):
            parse_record(valid_service_record(), snapshot_bound)

    def test_requires_source_authorization_for_record_kind(self) -> None:
        value = valid_service_record()
        value["kind"] = "registry"
        self.assert_rejected(value, "unsupported kind: registry")

    def test_enforces_kind_specific_service_and_probe_fields(self) -> None:
        value = valid_service_record()
        value["body"]["pattern"] = None  # type: ignore[index]
        self.assert_rejected(value, "exactly one of pattern or pattern_hex is required")

        value = valid_service_record()
        value["kind"] = "active_probe"
        self.assert_rejected(value, "active_probe body")

        value = valid_service_record()
        value["body"]["confidence"] = float("nan")  # type: ignore[index]
        self.assert_rejected(value, "confidence must be finite")

    def test_preserves_binary_service_match_patterns_as_hex(self) -> None:
        value = valid_service_record()
        value["body"]["matcher_type"] = "prefix"  # type: ignore[index]
        value["body"]["pattern"] = None  # type: ignore[index]
        value["body"]["pattern_hex"] = "1603"  # type: ignore[index]
        value["id"] = stable_record_id(value)
        record = parse_record(value, SOURCES)
        self.assertIsNone(record.body.pattern)  # type: ignore[union-attr]
        self.assertEqual(record.body.pattern_hex, "1603")  # type: ignore[union-attr]

        binary_regex = valid_service_record()
        binary_regex["body"]["pattern"] = None  # type: ignore[index]
        binary_regex["body"]["pattern_hex"] = "00414243"  # type: ignore[index]
        binary_regex["id"] = stable_record_id(binary_regex)
        parsed_regex = parse_record(binary_regex, SOURCES)
        self.assertIsNone(parsed_regex.body.pattern)  # type: ignore[union-attr]
        self.assertEqual(parsed_regex.body.pattern_hex, "00414243")  # type: ignore[union-attr]

        textual_regex = valid_service_record()
        hexadecimal_regex = copy.deepcopy(textual_regex)
        hexadecimal_regex["body"]["pattern"] = None  # type: ignore[index]
        hexadecimal_regex["body"]["pattern_hex"] = textual_regex["body"]["pattern"].encode().hex()  # type: ignore[index,union-attr]
        self.assertEqual(stable_record_id(textual_regex), stable_record_id(hexadecimal_regex))
        hexadecimal_regex["id"] = stable_record_id(hexadecimal_regex)
        normalized_regex = parse_record(hexadecimal_regex, SOURCES)
        self.assertEqual(
            normalized_regex.body.pattern,  # type: ignore[union-attr]
            textual_regex["body"]["pattern"],  # type: ignore[index]
        )
        self.assertIsNone(normalized_regex.body.pattern_hex)  # type: ignore[union-attr]

        literal = valid_service_record()
        literal["body"]["matcher_type"] = "prefix"  # type: ignore[index]
        literal["body"]["pattern"] = "HTTP/"  # type: ignore[index]
        encoded = copy.deepcopy(literal)
        encoded["body"]["pattern"] = None  # type: ignore[index]
        encoded["body"]["pattern_hex"] = "485454502f"  # type: ignore[index]
        self.assertEqual(stable_record_id(literal), stable_record_id(encoded))

        value["body"]["pattern_hex"] = "16GG"  # type: ignore[index]
        self.assert_rejected(value, "pattern_hex must be lowercase")

    def test_rejects_runtime_incompatible_regex_at_canonical_boundary(self) -> None:
        for pattern in ("(unclosed", "[z-a]", "a**", "a++", "a{2,1}"):
            with self.subTest(pattern=pattern):
                value = valid_service_record()
                value["body"]["pattern"] = pattern  # type: ignore[index]
                self.assert_rejected(value, "regex is not runtime-compatible")

        value = valid_service_record()
        value["body"]["pattern"] = None  # type: ignore[index]
        value["body"]["pattern_hex"] = b"a**".hex()  # type: ignore[index]
        self.assert_rejected(value, "regex is not runtime-compatible")

    def test_rejects_character_class_with_more_than_runtime_capture_bound_parentheses(self) -> None:
        self.assertFalse(runtime_regex_is_valid(b"[" + (b"(" * 17) + b"]"))

    def test_rejects_oversized_regex_repeat_without_leaking_an_overflow(self) -> None:
        self.assertFalse(runtime_regex_is_valid(b"a{999999999999999999999999999999}"))

    def test_enforces_active_and_udp_runtime_bounds(self) -> None:
        value = valid_active_probe_record()
        value["body"]["priority"] = True  # type: ignore[index]
        self.assert_rejected(value, "priority must be an integer")

        value = valid_active_probe_record()
        value["body"]["payload_hex"] = "ABC0"  # type: ignore[index]
        self.assert_rejected(value, "payload_hex must be lowercase")

        value = valid_active_probe_record()
        value["body"]["fallback_probe_names"] = ["fallback"] * 17  # type: ignore[index]
        self.assert_rejected(value, "fallback_probe_names exceeds 16 entries")

        value = valid_active_probe_record()
        value["body"]["fallback_probe_names"] = ["Generic.Banner"]  # type: ignore[index]
        self.assert_rejected(value, "fallback probe name is not runtime-compatible")

        value = valid_active_probe_record()
        value["body"]["timeout_ms"] = None  # type: ignore[index]
        value["id"] = stable_record_id(value)
        self.assertIsNone(parse_record(value, SOURCES).body.timeout_ms)

        value = valid_active_probe_record()
        value["body"]["payload_hex"] = "00" * 4001  # type: ignore[index]
        self.assert_rejected(value, "payload_hex exceeds 4000 decoded bytes")

        value = valid_udp_probe_record()
        value["body"]["payload_hex"] = ""  # type: ignore[index]
        self.assert_rejected(value, "payload_hex must be lowercase")

        value = valid_udp_probe_record()
        value["body"]["payload_hex"] = "00" * 513  # type: ignore[index]
        self.assert_rejected(value, "payload_hex exceeds 512 decoded bytes")

        value = valid_udp_probe_record()
        value["body"]["destination_port"] = 0  # type: ignore[index]
        self.assert_rejected(value, "port 0 is reserved for DEFAULT")

        value = valid_udp_probe_record()
        value["body"]["name"] = "DNS probe"  # type: ignore[index]
        self.assert_rejected(value, "name must be a runtime token")

        value = valid_udp_probe_record()
        value["body"]["protocol_hint"] = "dns#comment"  # type: ignore[index]
        self.assert_rejected(value, "protocol_hint must be a runtime token")

    def test_parses_typed_os_signatures_and_rejects_invalid_ranges(self) -> None:
        record = parse_record(valid_os_record(), SOURCES)
        self.assertIsInstance(record.body, OSFingerprintSemantics)
        self.assertEqual(record.body.signatures[0].value, (45, 64))

        value = valid_os_record()
        signature = value["body"]["signatures"][0]  # type: ignore[index]
        signature["value"] = [65, 64]
        self.assert_rejected(value, "signature minimum must not exceed maximum")

        value = valid_os_record()
        value["body"]["signatures"].append(  # type: ignore[index,union-attr]
            {"field": "ttl", "operator": "eq", "value": 64}
        )
        self.assert_rejected(value, "signatures contains duplicate fields")

        value = valid_os_record()
        value["body"]["signatures"][0]["operator"] = "bool"  # type: ignore[index]
        value["body"]["signatures"][0]["value"] = True  # type: ignore[index]
        self.assert_rejected(value, "operator is incompatible with field")

        value = valid_os_record()
        value["body"]["address_family"] = "ipv6"  # type: ignore[index]
        value["body"]["signatures"] = [  # type: ignore[index]
            {"field": "dont_fragment", "operator": "bool", "value": True}
        ]
        self.assert_rejected(value, "IPv6 fingerprints cannot contain dont_fragment")

    def test_os_signature_contract_matches_runtime_loader(self) -> None:
        value = valid_os_record()
        value["body"]["signatures"] = [  # type: ignore[index]
            {"field": "mss", "operator": "range", "value": [1200, 1460]}
        ]
        self.assert_rejected(value, "operator is incompatible with field")

        value = valid_os_record()
        value["body"]["signatures"] = [  # type: ignore[index]
            {"field": "tcp_flags", "operator": "text", "value": "SYN_ACK"}
        ]
        self.assert_rejected(value, "operator is incompatible with field")

        for options in ([], ["UNKNOWN"]):
            with self.subTest(options=options):
                value = valid_os_record()
                value["body"]["signatures"] = [  # type: ignore[index]
                    {"field": "tcp_options", "operator": "tcp_options", "value": options}
                ]
                self.assert_rejected(value, "TCP options")

        value = valid_os_record()
        value["body"]["signatures"] = [  # type: ignore[index]
            {"field": "ack_behavior", "operator": "text", "value": "BOGUS"}
        ]
        self.assert_rejected(value, "value is not a recognized runtime behavior")

    def test_os_optional_class_fields_match_runtime_loader(self) -> None:
        value = valid_os_record()
        value["body"]["os_generation"] = ""  # type: ignore[index]
        value["body"]["device_type"] = ""  # type: ignore[index]
        value["id"] = stable_record_id(value)
        record = parse_record(value, SOURCES)
        self.assertEqual(record.body.os_generation, "")
        self.assertEqual(record.body.device_type, "")

        value = valid_os_record()
        value["body"]["os_generation"] = ""  # type: ignore[index]
        self.assert_rejected(value, "device_type requires os_generation")

        value = valid_os_record()
        value["body"]["vendor"] = "Linux | forged"  # type: ignore[index]
        self.assert_rejected(value, "vendor contains a runtime delimiter")

        value = valid_os_record()
        value["body"]["vendor"] = " Linux"  # type: ignore[index]
        self.assert_rejected(value, "vendor must not have edge whitespace")

        value = valid_os_record()
        value["body"]["signatures"] = [  # type: ignore[index]
            {"field": "ack_behavior", "operator": "text", "value": "NO_ACK "}
        ]
        self.assert_rejected(value, "value must not have edge whitespace")

    def test_rejects_non_nfc_text_and_resource_overflow(self) -> None:
        value = valid_service_record()
        value["notes"] = "Cafe\u0301"
        self.assert_rejected(value, "notes must be NFC-normalized")

        value = valid_service_record()
        value["notes"] = "safe\nforged"
        self.assert_rejected(value, "notes contains unsafe control characters")

        value = valid_service_record()
        value["body"]["pattern"] = "x" * 513  # type: ignore[index]
        self.assert_rejected(value, "pattern exceeds 512 bytes")

        value = valid_service_record()
        value["body"]["cpe"] = [f"cpe:/a:vendor:p{i}" for i in range(65)]  # type: ignore[index]
        self.assert_rejected(value, "cpe exceeds 64 entries")

        value = valid_service_record()
        value["first_imported_revision"] = "main"
        self.assert_rejected(value, "first_imported_revision must identify an immutable revision")

    def test_rejects_duplicate_set_fields(self) -> None:
        value = valid_service_record()
        value["body"]["cpe"] = ["cpe:/a:apache:http_server"] * 2  # type: ignore[index]
        self.assert_rejected(value, "cpe contains duplicates")


if __name__ == "__main__":
    unittest.main()
