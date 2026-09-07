import json
import tempfile
import unittest
from pathlib import Path

from tools.corpus.sources import load_source_manifest


class SourceManifestTests(unittest.TestCase):
    def write_manifest(self, payload: dict) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "sources.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def valid_source() -> dict:
        return {
            "id": "skan-first-party",
            "name": "Skan first-party corpus",
            "homepage": "https://github.com/Adam-Ghanem/Skan",
            "source_url": "https://github.com/Adam-Ghanem/Skan/tree/main/data",
            "license_spdx_or_policy": "MIT",
            "redistribution_allowed": True,
            "attribution_required": False,
            "approved_data_classes": [
                "service_matcher",
                "active_probe",
                "os_fingerprint",
                "udp_probe",
            ],
            "blocked_data_classes": [],
            "pinned_revision": "repository",
            "expected_hash": None,
            "adapter": "skan_existing",
            "notes": "Repository-owned baseline data",
        }

    def test_loads_approved_source(self):
        path = self.write_manifest(
            {"schema_version": 1, "sources": [self.valid_source()]}
        )
        sources = load_source_manifest(path)
        source = sources["skan-first-party"]
        self.assertEqual(source.license_spdx_or_policy, "MIT")
        self.assertTrue(source.redistribution_allowed)
        self.assertEqual(source.approved_data_classes[0], "service_matcher")

    def test_rejects_duplicate_source_ids(self):
        source = self.valid_source()
        path = self.write_manifest(
            {"schema_version": 1, "sources": [source, source]}
        )
        with self.assertRaisesRegex(ValueError, "duplicate source id"):
            load_source_manifest(path)

    def test_rejects_redistribution_without_license(self):
        source = self.valid_source()
        source["license_spdx_or_policy"] = ""
        path = self.write_manifest({"schema_version": 1, "sources": [source]})
        with self.assertRaisesRegex(ValueError, "license"):
            load_source_manifest(path)

    def test_rejects_string_boolean_instead_of_json_boolean(self):
        source = self.valid_source()
        source["redistribution_allowed"] = "false"
        path = self.write_manifest({"schema_version": 1, "sources": [source]})
        with self.assertRaisesRegex(ValueError, "redistribution_allowed must be boolean"):
            load_source_manifest(path)

    def test_rejects_invalid_expected_hash(self):
        source = self.valid_source()
        source["expected_hash"] = "sha256:xyz"
        path = self.write_manifest({"schema_version": 1, "sources": [source]})
        with self.assertRaisesRegex(ValueError, "expected_hash"):
            load_source_manifest(path)

    def test_rejects_unsupported_schema_version(self):
        path = self.write_manifest(
            {"schema_version": 2, "sources": [self.valid_source()]}
        )
        with self.assertRaisesRegex(ValueError, "schema_version"):
            load_source_manifest(path)


if __name__ == "__main__":
    unittest.main()
