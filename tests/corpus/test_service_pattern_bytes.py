from __future__ import annotations

import unittest

from tools.corpus.model import (
    CanonicalRecordError,
    parse_record,
    stable_record_id,
)
from tools.corpus.sources import load_source_manifest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCES = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")
REVISION = "git:399abe4821e9ce9138f53b0cb8a769d75329ba1f"
SOURCE_URL = (
    "https://github.com/Adam-Ghanem/Skan/tree/"
    "399abe4821e9ce9138f53b0cb8a769d75329ba1f/data"
)


def service_record(
    *,
    matcher_type: str = "regex",
    pattern: str | None = None,
    pattern_hex: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 2,
        "id": "",
        "kind": "service_matcher",
        "body": {
            "probe_name": "BinaryProbe",
            "matcher_type": matcher_type,
            "pattern": pattern,
            "pattern_hex": pattern_hex,
            "strength": "hard",
            "service": "binary-test",
            "product": None,
            "version_template": None,
            "extra": None,
            "hostname_template": None,
            "tunnel": None,
            "confidence": 0.9,
            "rule_order": 0,
            "cpe": [],
        },
        "provenance": [
            {
                "source_id": "skan-first-party",
                "source_record_id": "service:BinaryProbe:0",
                "source_revision": REVISION,
                "source_url": SOURCE_URL,
                "source_license": "MIT",
                "snapshot_hash": None,
                "record_hash": "sha256:" + ("1" * 64),
            }
        ],
        "first_imported_revision": REVISION,
        "last_verified_revision": REVISION,
        "status": "imported",
        "notes": "Byte-exact matcher test.",
    }
    value["id"] = stable_record_id(value)
    return value


class ServicePatternByteContractTests(unittest.TestCase):
    def test_regex_accepts_binary_pattern_hex_and_preserves_raw_bytes(self) -> None:
        value = service_record(pattern_hex="5e44656d6f2f0028ff29")
        record = parse_record(value, SOURCES)
        self.assertIsNone(record.body.pattern)  # type: ignore[union-attr]
        self.assertEqual(
            record.body.pattern_hex,  # type: ignore[union-attr]
            "5e44656d6f2f0028ff29",
        )

    def test_text_and_hex_regex_forms_share_one_semantic_identity(self) -> None:
        textual = service_record(pattern="^HTTP/([0-9.]+)")
        binary = service_record(pattern_hex="5e485454502f285b302d392e5d2b29")
        self.assertEqual(stable_record_id(textual), stable_record_id(binary))
        parsed = parse_record(textual, SOURCES)
        self.assertIsNone(parsed.body.pattern)  # type: ignore[union-attr]
        self.assertEqual(
            parsed.body.pattern_hex,  # type: ignore[union-attr]
            "5e485454502f285b302d392e5d2b29",
        )

    def test_regex_byte_limit_matches_runtime_limit(self) -> None:
        value = service_record(pattern_hex="61")
        value["body"]["pattern_hex"] = "61" * 513  # type: ignore[index]
        with self.assertRaisesRegex(CanonicalRecordError, "exceeds 512 decoded bytes"):
            stable_record_id(value)

    def test_non_regex_matcher_keeps_full_runtime_pattern_bound(self) -> None:
        value = service_record(
            matcher_type="prefix",
            pattern_hex="61" * 4096,
        )
        record = parse_record(value, SOURCES)
        self.assertEqual(len(record.body.pattern_hex or "") // 2, 4096)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
