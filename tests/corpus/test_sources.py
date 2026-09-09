from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.sources import CorpusManifestError, load_source_manifest


PINNED_REVISION = "git:399abe4821e9ce9138f53b0cb8a769d75329ba1f"
SNAPSHOT_HASH = "sha256:" + ("a" * 64)


def valid_source() -> dict[str, object]:
    return {
        "id": "skan-first-party",
        "source_class": "first_party",
        "name": "Skan first-party corpus",
        "homepage": "https://github.com/Adam-Ghanem/Skan",
        "source_url": (
            "https://github.com/Adam-Ghanem/Skan/tree/"
            "399abe4821e9ce9138f53b0cb8a769d75329ba1f/data"
        ),
        "license_spdx_or_policy": "MIT",
        "redistribution_allowed": True,
        "attribution_required": False,
        "attribution_notice": None,
        "approved_data_classes": [
            "active_probe",
            "os_fingerprint",
            "service_matcher",
            "udp_probe",
        ],
        "blocked_data_classes": [],
        "pinned_revision": PINNED_REVISION,
        "expected_hash": None,
        "adapter": "skan_first_party",
        "notes": "Repository-owned runtime corpus.",
    }


def manifest(source: dict[str, object] | None = None) -> dict[str, object]:
    return {"schema_version": 1, "sources": [source or valid_source()]}


class SourceManifestTests(unittest.TestCase):
    def load_raw(self, value: bytes):
        with tempfile.TemporaryDirectory(prefix="skan-source-policy-") as directory:
            path = Path(directory) / "sources.json"
            path.write_bytes(value)
            return load_source_manifest(path)

    def load(self, value: dict[str, object]):
        with tempfile.TemporaryDirectory(prefix="skan-source-policy-") as directory:
            path = Path(directory) / "sources.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return load_source_manifest(path)

    def assert_rejected(self, value: dict[str, object], message: str) -> None:
        with self.assertRaisesRegex(CorpusManifestError, message):
            self.load(value)

    def test_loads_pinned_first_party_policy(self) -> None:
        sources = self.load(manifest())
        policy = sources["skan-first-party"]
        self.assertEqual(policy.pinned_revision, PINNED_REVISION)
        self.assertEqual(policy.source_class, "first_party")
        self.assertEqual(policy.approved_data_classes[0], "active_probe")
        self.assertFalse(policy.attribution_required)

    def test_repository_manifest_is_valid_and_offline(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(repository_root / "corpus" / "sources" / "sources.json")
        self.assertEqual(tuple(sources), ("skan-first-party",))
        self.assertEqual(sources["skan-first-party"].adapter, "skan_first_party")

    def test_rejects_unknown_root_and_source_fields(self) -> None:
        unknown_root = manifest()
        unknown_root["download_url"] = "https://example.invalid"
        self.assert_rejected(unknown_root, "manifest: unknown fields: download_url")

        source = valid_source()
        source["command"] = "run-me"
        self.assert_rejected(manifest(source), r"sources\[0\].*unknown fields: command")

    def test_rejects_path_capable_or_malformed_source_ids(self) -> None:
        for source_id in ("../outside", "nested/source", "UPPER", "", ".hidden"):
            with self.subTest(source_id=source_id):
                source = valid_source()
                source["id"] = source_id
                self.assert_rejected(manifest(source), "invalid source id")

    def test_rejects_duplicate_sources(self) -> None:
        value = manifest()
        value["sources"] = [valid_source(), copy.deepcopy(valid_source())]
        self.assert_rejected(value, "duplicate source id: skan-first-party")

    def test_rejects_unknown_overlapping_or_duplicate_data_classes(self) -> None:
        source = valid_source()
        source["approved_data_classes"] = ["service_matcher", "unknown"]
        self.assert_rejected(manifest(source), "unsupported approved data class: unknown")

        source = valid_source()
        source["blocked_data_classes"] = ["service_matcher"]
        self.assert_rejected(manifest(source), "approved and blocked data classes overlap")

        source = valid_source()
        source["approved_data_classes"] = ["service_matcher", "service_matcher"]
        self.assert_rejected(manifest(source), "approved_data_classes contains duplicates")

    def test_requires_immutable_revision_for_every_source(self) -> None:
        source = valid_source()
        source["pinned_revision"] = None
        self.assert_rejected(manifest(source), "pinned_revision is required")

        source = valid_source()
        source["pinned_revision"] = "main"
        self.assert_rejected(manifest(source), "pinned_revision must identify an immutable revision")

    def test_requires_snapshot_hash_for_external_sources(self) -> None:
        source = valid_source()
        source["id"] = "rfc-793"
        source["source_class"] = "standards"
        source["adapter"] = "rfc_fixture"
        source["expected_hash"] = None
        self.assert_rejected(manifest(source), "external source expected_hash is required")

        source["expected_hash"] = "sha256:not-a-digest"
        self.assert_rejected(manifest(source), "expected_hash must be sha256")

        source["expected_hash"] = SNAPSHOT_HASH
        loaded = self.load(manifest(source))
        self.assertEqual(loaded["rfc-793"].expected_hash, SNAPSHOT_HASH)

    def test_rejects_non_redistributable_sources(self) -> None:
        source = valid_source()
        source["redistribution_allowed"] = False
        self.assert_rejected(manifest(source), "redistribution_allowed must be true")

    def test_first_party_identity_is_bound_to_skan_repository(self) -> None:
        source = valid_source()
        source["id"] = "pretend-first-party"
        self.assert_rejected(manifest(source), "untrusted first_party source identity")

        source = valid_source()
        source["source_url"] = (
            "https://example.invalid/Adam-Ghanem/Skan/tree/"
            "399abe4821e9ce9138f53b0cb8a769d75329ba1f/data"
        )
        self.assert_rejected(manifest(source), "untrusted first_party source URL")

        source = valid_source()
        source["source_url"] = (
            "https://github.com:invalid/Adam-Ghanem/Skan/tree/"
            "399abe4821e9ce9138f53b0cb8a769d75329ba1f/data"
        )
        self.assert_rejected(manifest(source), "source_url must use https")

    def test_git_pin_must_be_an_exact_url_path_segment(self) -> None:
        source = valid_source()
        source["source_url"] = (
            "https://github.com/Adam-Ghanem/Skan/tree/main/data?revision="
            "399abe4821e9ce9138f53b0cb8a769d75329ba1f"
        )
        self.assert_rejected(manifest(source), "pinned git revision must be an exact URL path segment")

    def test_rejects_unapproved_license_policy(self) -> None:
        source = valid_source()
        source["license_spdx_or_policy"] = "Proprietary-Unreviewed"
        self.assert_rejected(manifest(source), "unsupported license policy")

    def test_rejects_duplicate_json_fields_and_manifest_size_overflow(self) -> None:
        duplicate = b'{"schema_version":1,"schema_version":1,"sources":[]}'
        with self.assertRaisesRegex(CorpusManifestError, "duplicate JSON field"):
            self.load_raw(duplicate)

        oversized = b" " * ((256 * 1024) + 1)
        with self.assertRaisesRegex(CorpusManifestError, "source manifest exceeds"):
            self.load_raw(oversized)

    def test_enforces_source_count_and_text_bounds(self) -> None:
        too_many = manifest()
        too_many["sources"] = [copy.deepcopy(valid_source()) for _ in range(257)]
        self.assert_rejected(too_many, "sources exceeds 256 entries")

        source = valid_source()
        source["notes"] = "x" * 4097
        self.assert_rejected(manifest(source), "notes exceeds 4096 bytes")

    def test_requires_attribution_notice_when_policy_requires_it(self) -> None:
        source = valid_source()
        source["id"] = "vendor-docs"
        source["source_class"] = "vendor"
        source["adapter"] = "vendor_fixture"
        source["expected_hash"] = SNAPSHOT_HASH
        source["attribution_required"] = True
        source["attribution_notice"] = None
        self.assert_rejected(manifest(source), "attribution_notice is required")

        source["attribution_notice"] = "Vendor documentation attribution."
        loaded = self.load(manifest(source))
        self.assertEqual(
            loaded["vendor-docs"].attribution_notice,
            "Vendor documentation attribution.",
        )

    def test_rejects_non_https_urls_and_unsafe_adapter_names(self) -> None:
        source = valid_source()
        source["source_url"] = "http://example.invalid/data"
        self.assert_rejected(manifest(source), "source_url must use https")

        source = valid_source()
        source["adapter"] = "../../execute"
        self.assert_rejected(manifest(source), "invalid adapter name")

        source = valid_source()
        source["source_url"] = "https://[invalid/path"
        self.assert_rejected(manifest(source), "source_url must use https")

        source = valid_source()
        source["id"] = "external-fixture"
        source["source_class"] = "vendor"
        source["source_url"] = (
            "https://example.invalid:invalid/data/"
            "399abe4821e9ce9138f53b0cb8a769d75329ba1f"
        )
        source["expected_hash"] = SNAPSHOT_HASH
        source["adapter"] = "external_fixture"
        self.assert_rejected(manifest(source), "source_url must use https")


if __name__ == "__main__":
    unittest.main()
