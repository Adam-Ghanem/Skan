from __future__ import annotations

from collections import Counter
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.recog import parse_recog_xml
from tools.corpus.attribution import render_notices
from tools.corpus.compile_external import compile_records
from tools.corpus.external_io import load_jsonl, write_jsonl
from tools.corpus.external_layout import EXTERNAL_STORE_FILES
from tools.corpus.external_manifest import write_external_manifest
from tools.corpus.external_model import CanonicalRecord, stable_record_id
from tools.corpus.external_sources import load_source_manifest
from tools.corpus.external_integrity import verify_external_repository


_SOURCE_ID = "rapid7-recog"
_REVISION = "r1"
_SOURCE_URL = "https://example.invalid/recog"
_LICENSE = "BSD-2-Clause"
_DIGEST = "a" * 64
_DETECTION_KINDS = {
    "service_matcher",
    "active_probe",
    "os_fingerprint",
    "udp_probe",
    "web_fingerprint",
    "device_fingerprint",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


class ExternalRepositoryFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.external = root / "corpus/external"
        self.locks = root / "corpus/locks"
        self.stats = root / "corpus/reports/external-stats.json"
        self.notices = root / "corpus/THIRD_PARTY_NOTICES.md"
        self.source_manifest = root / "corpus/sources/external-sources.json"
        for directory in (self.external, self.locks, self.stats.parent, self.source_manifest.parent):
            directory.mkdir(parents=True, exist_ok=True)

        source = {
            "id": _SOURCE_ID,
            "name": "Rapid7 Recog fixture",
            "homepage": "https://example.invalid/",
            "source_url": _SOURCE_URL,
            "license_spdx_or_policy": _LICENSE,
            "redistribution_allowed": True,
            "attribution_required": True,
            "approved_data_classes": ["service_matcher"],
            "blocked_data_classes": [],
            "pinned_revision": _REVISION,
            "expected_hash": None,
            "adapter": "recog",
            "notes": "fixture",
        }
        self.source_manifest.write_bytes(
            _canonical_json({"schema_version": 1, "sources": [source]})
        )
        self.sources = load_source_manifest(self.source_manifest)
        context = AdapterContext(
            source_id=_SOURCE_ID,
            revision=_REVISION,
            source_url=_SOURCE_URL,
            source_license=_LICENSE,
            source_hash="sha256:" + _DIGEST,
        )
        self.records = parse_recog_xml(
            '<fingerprints matches="ftp.banner" protocol="ftp">'
            '<fingerprint pattern="DemoFTP"><param pos="0" name="service.product" '
            'value="Demo FTP"/></fingerprint></fingerprints>',
            context,
            source_path="ftp.xml",
        )
        compile_records(self.records, self.external, self.sources)
        self._write_lock()
        self._write_stats(self.records)
        self.notices.write_text(
            render_notices(self.records, self.sources), encoding="utf-8", newline="\n"
        )

    def _write_lock(self, **changes: object) -> None:
        value: dict[str, object] = {
            "schema_version": 1,
            "source_id": _SOURCE_ID,
            "revision": _REVISION,
            "source_url": _SOURCE_URL,
            "sha256": _DIGEST,
            "adapter_version": 1,
            "license_policy": _LICENSE,
            "attribution": "Rapid7 Recog",
        }
        value.update(changes)
        (self.locks / f"{_SOURCE_ID}.json").write_bytes(_canonical_json(value))

    def _load_by_file(self) -> dict[str, list[CanonicalRecord]]:
        return {
            name: load_jsonl(self.external / name, self.sources)
            for name in EXTERNAL_STORE_FILES
        }

    def _write_manifest(self, records_by_file: dict[str, list[CanonicalRecord]]) -> None:
        write_external_manifest(self.external, records_by_file)

    def _write_stats(
        self,
        records: list[CanonicalRecord],
        **changes: object,
    ) -> None:
        counts = Counter(record.kind for record in records)
        files = {
            name: len(load_jsonl(self.external / name, self.sources))
            for name in EXTERNAL_STORE_FILES
        }
        value: dict[str, object] = {
            "total_records": len(records),
            "records_by_kind": dict(sorted(counts.items())),
            "files": files,
            "detection_records": sum(
                1 for record in records if record.kind in _DETECTION_KINDS
            ),
            "port_registry_records": sum(
                1 for record in records if record.kind == "port_registry"
            ),
            "conflict_count": 0,
            "refresh_diagnostic": "allowed",
        }
        value.update(changes)
        self.stats.write_bytes(_canonical_json(value))


class ExternalIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = ExternalRepositoryFixture(Path(self.temporary.name))

    def assert_invalid(self, fragment: str) -> None:
        with self.assertRaisesRegex(ValueError, fragment):
            verify_external_repository(self.fixture.root)

    def test_complete_repository_returns_recomputed_summary(self) -> None:
        summary = verify_external_repository(self.fixture.root)

        self.assertEqual(
            summary,
            {
                "conflict_count": 0,
                "detection_records": 1,
                "files": {
                    "cpe.jsonl": 0,
                    "devices.jsonl": 0,
                    "os.jsonl": 0,
                    "products.jsonl": 0,
                    "registry.jsonl": 0,
                    "services.jsonl": 1,
                    "udp.jsonl": 0,
                    "web.jsonl": 0,
                },
                "port_registry_records": 0,
                "records_by_kind": {"service_matcher": 1},
                "total_records": 1,
            },
        )

    def test_cli_prints_one_compact_json_summary(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.corpus.external_integrity",
                "--root",
                str(self.fixture.root),
            ],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertEqual(json.loads(completed.stdout), verify_external_repository(self.fixture.root))
        self.assertEqual(completed.stderr, "")

    def test_stale_statistics_are_rejected(self) -> None:
        self.fixture._write_stats(self.fixture.records, total_records=2)
        self.assert_invalid("statistics.*total_records")

    def test_statistics_reject_boolean_nested_count(self) -> None:
        statistics = json.loads(self.fixture.stats.read_text(encoding="utf-8"))
        statistics["files"]["services.jsonl"] = True
        self.fixture.stats.write_bytes(_canonical_json(statistics))

        self.assert_invalid("statistics.*files")

    def test_missing_store_is_rejected(self) -> None:
        (self.fixture.external / "udp.jsonl").unlink()
        self.assert_invalid("external store.*udp.jsonl")

    def test_modified_store_hash_is_rejected(self) -> None:
        path = self.fixture.external / "services.jsonl"
        path.write_bytes(path.read_bytes().replace(b"\n", b" \n"))
        self.assert_invalid("manifest.*services.jsonl.*sha256")

    def test_extra_jsonl_store_is_rejected(self) -> None:
        (self.fixture.external / "unexpected.jsonl").write_bytes(b"")
        self.assert_invalid("unexpected.jsonl")

    def test_duplicate_id_across_stores_is_rejected(self) -> None:
        service_path = self.fixture.external / "services.jsonl"
        product_path = self.fixture.external / "products.jsonl"
        product_path.write_bytes(service_path.read_bytes())
        by_file = self.fixture._load_by_file()
        self.fixture._write_manifest(by_file)

        self.assert_invalid("duplicate external record id")

    def test_unresolved_merge_conflict_is_rejected(self) -> None:
        original = self.fixture.records[0]
        conflicting = replace(original, id="", product="Conflicting FTP")
        conflicting = replace(conflicting, id=stable_record_id(conflicting))
        products = self.fixture.external / "products.jsonl"
        write_jsonl(products, [conflicting])
        by_file = self.fixture._load_by_file()
        self.fixture._write_manifest(by_file)

        self.assert_invalid("unresolved external corpus conflict")

    def test_provenance_revision_disagrees_with_lock(self) -> None:
        self.fixture._write_lock(revision="wrong")
        self.assert_invalid("rapid7-recog.*revision")

    def test_provenance_hash_disagrees_with_lock(self) -> None:
        self.fixture._write_lock(sha256="b" * 64)
        self.assert_invalid("rapid7-recog.*sha256")

    def test_missing_notices_are_rejected(self) -> None:
        self.fixture.notices.unlink()
        self.assert_invalid("notices")

    def test_stale_notices_are_rejected(self) -> None:
        self.fixture.notices.write_text("stale\n", encoding="utf-8")
        self.assert_invalid("notices")

    def test_malformed_governed_json_is_rejected(self) -> None:
        for artifact, label in (
            ("manifest", "external manifest"),
            ("stats", "external statistics"),
            ("lock", "source lock"),
        ):
            with self.subTest(artifact=artifact):
                fixture = ExternalRepositoryFixture(Path(self.temporary.name) / artifact)
                target = {
                    "manifest": fixture.external / "manifest.json",
                    "stats": fixture.stats,
                    "lock": fixture.locks / f"{_SOURCE_ID}.json",
                }[artifact]
                target.write_bytes(b"{broken\n")
                with self.assertRaisesRegex(ValueError, label):
                    verify_external_repository(fixture.root)

    def test_duplicate_key_governed_json_is_rejected(self) -> None:
        for artifact in ("manifest", "stats", "lock"):
            with self.subTest(artifact=artifact):
                fixture = ExternalRepositoryFixture(Path(self.temporary.name) / artifact)
                target = {
                    "manifest": fixture.external / "manifest.json",
                    "stats": fixture.stats,
                    "lock": fixture.locks / f"{_SOURCE_ID}.json",
                }[artifact]
                target.write_bytes(b'{"schema_version":1,"schema_version":1}\n')
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    verify_external_repository(fixture.root)

    def test_oversized_governed_json_is_rejected(self) -> None:
        cases = (
            ("manifest", 128 * 1024),
            ("stats", 1024 * 1024),
            ("lock", 64 * 1024),
        )
        for artifact, limit in cases:
            with self.subTest(artifact=artifact):
                fixture = ExternalRepositoryFixture(Path(self.temporary.name) / artifact)
                target = {
                    "manifest": fixture.external / "manifest.json",
                    "stats": fixture.stats,
                    "lock": fixture.locks / f"{_SOURCE_ID}.json",
                }[artifact]
                target.write_bytes(b" " * (limit + 1))
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    verify_external_repository(fixture.root)

    def test_symlinked_governed_json_is_rejected(self) -> None:
        for artifact in ("manifest", "stats", "lock"):
            with self.subTest(artifact=artifact):
                fixture = ExternalRepositoryFixture(Path(self.temporary.name) / artifact)
                target = {
                    "manifest": fixture.external / "manifest.json",
                    "stats": fixture.stats,
                    "lock": fixture.locks / f"{_SOURCE_ID}.json",
                }[artifact]
                replacement = target.with_name(target.name + ".real")
                target.replace(replacement)
                try:
                    os.symlink(replacement, target)
                except OSError as exc:
                    self.skipTest(f"symlinks are unavailable: {exc}")
                with self.assertRaisesRegex(ValueError, "symlink"):
                    verify_external_repository(fixture.root)

    def test_noncanonical_or_non_lf_manifest_is_rejected(self) -> None:
        path = self.fixture.external / "manifest.json"
        parsed = json.loads(path.read_text(encoding="utf-8"))
        path.write_bytes((json.dumps(parsed, indent=2) + "\n").encode("utf-8"))
        self.assert_invalid("manifest.*canonical")

        self.fixture._write_manifest(self.fixture._load_by_file())
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self.assert_invalid("manifest.*LF")

    def test_nonfinite_governed_json_is_rejected(self) -> None:
        self.fixture.stats.write_bytes(b'{"total_records":NaN}\n')
        self.assert_invalid("non-finite")


if __name__ == "__main__":
    unittest.main()
