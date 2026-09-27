from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.iana_services import parse_iana_csv
from tools.corpus.adapters.recog import parse_recog_xml
from tools.corpus.adapters.wappalyzer import parse_wappalyzer_json
from tools.corpus.compile_external import compile_records
from tools.corpus.external_io import load_jsonl
from tools.corpus.external_layout import EXTERNAL_KIND_FILES, EXTERNAL_STORE_FILES
from tools.corpus.external_manifest import write_external_manifest
from tools.corpus.external_sources import load_source_manifest


class ExternalCompilerTests(unittest.TestCase):
    def test_external_layout_exposes_exact_immutable_store_contract(self) -> None:
        self.assertEqual(
            EXTERNAL_STORE_FILES,
            (
                "cpe.jsonl",
                "devices.jsonl",
                "os.jsonl",
                "products.jsonl",
                "registry.jsonl",
                "services.jsonl",
                "udp.jsonl",
                "web.jsonl",
            ),
        )
        self.assertEqual(EXTERNAL_KIND_FILES["service_matcher"], "services.jsonl")
        self.assertEqual(EXTERNAL_KIND_FILES["active_probe"], "services.jsonl")
        self.assertEqual(set(EXTERNAL_KIND_FILES.values()), set(EXTERNAL_STORE_FILES))
        with self.assertRaises(TypeError):
            EXTERNAL_KIND_FILES["service_matcher"] = "other.jsonl"  # type: ignore[index]

    def test_compiler_writes_canonical_manifest_for_every_external_store(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/external-sources.json")
        recog_context = AdapterContext(
            "rapid7-recog",
            "v3.1.29",
            "https://example.invalid/ftp_banners.xml",
            "BSD-2-Clause",
            "sha256:" + "a" * 64,
        )
        iana_context = AdapterContext(
            "iana-services",
            "2026-09-04",
            "https://example.invalid/services.csv",
            "CC0-1.0",
            "sha256:" + "b" * 64,
        )
        wappalyzer_context = AdapterContext(
            "wappalyzergo",
            "c881bf2d7f88b11b9b32e2b0fdd050e638f6b20a",
            "https://example.invalid/wapp.json",
            "MIT",
            "sha256:" + "c" * 64,
        )
        records = [
            *parse_recog_xml(
                '<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="^Demo FTP$"><param pos="0" name="service.product" value="Demo"/></fingerprint></fingerprints>',
                recog_context,
                source_path="ftp_banners.xml",
            ),
            *parse_iana_csv(
                "Service Name,Port Number,Transport Protocol,Description\nexample,4242,tcp,Example Service\n",
                iana_context,
            ),
            *parse_wappalyzer_json(
                json.dumps({"apps": {"Demo": {"js": {"Demo": "x"}, "css": [".demo"], "dom": {"#demo": {"exists": ""}}}}}),
                wappalyzer_context,
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            summary = compile_records(records, output, sources)
            manifest_bytes = (output / "manifest.json").read_bytes()
            manifest = json.loads(manifest_bytes)

            self.assertEqual(summary["total_records"], 5)
            self.assertEqual(set(path.name for path in output.iterdir()), {*EXTERNAL_STORE_FILES, "manifest.json"})
            self.assertEqual(set(manifest), {"schema_version", "stores"})
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(set(manifest["stores"]), set(EXTERNAL_STORE_FILES))
            self.assertEqual(
                manifest["stores"]["services.jsonl"],
                {
                    "count": 1,
                    "kinds": {"service_matcher": 1},
                    "sha256": "sha256:" + hashlib.sha256((output / "services.jsonl").read_bytes()).hexdigest(),
                },
            )
            self.assertEqual(
                manifest["stores"]["registry.jsonl"],
                {
                    "count": 1,
                    "kinds": {"port_registry": 1},
                    "sha256": "sha256:" + hashlib.sha256((output / "registry.jsonl").read_bytes()).hexdigest(),
                },
            )
            self.assertEqual(
                manifest["stores"]["web.jsonl"],
                {
                    "count": 3,
                    "kinds": {"web_fingerprint": 3},
                    "sha256": "sha256:" + hashlib.sha256((output / "web.jsonl").read_bytes()).hexdigest(),
                },
            )
            for name in ("cpe.jsonl", "devices.jsonl", "os.jsonl", "products.jsonl", "udp.jsonl"):
                self.assertEqual((output / name).read_bytes(), b"")
                self.assertEqual(
                    manifest["stores"][name],
                    {
                        "count": 0,
                        "kinds": {},
                        "sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
                    },
                )
            expected_bytes = (
                json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                + b"\n"
            )
            self.assertEqual(manifest_bytes, expected_bytes)

    def test_manifest_writer_rejects_incomplete_store_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "exact external store set"):
                write_external_manifest(Path(tmp), {"services.jsonl": []})

    def test_groups_valid_records_deterministically_and_accepts_web_dimensions(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/external-sources.json")
        context = AdapterContext(
            source_id="wappalyzergo",
            revision="c881bf2d7f88b11b9b32e2b0fdd050e638f6b20a",
            source_url="https://example.invalid/wapp.json",
            source_license="MIT",
            source_hash="sha256:" + "c" * 64,
        )
        records = parse_wappalyzer_json(json.dumps({"apps": {"Demo": {"js": {"Demo": "x"}, "css": [".demo"], "dom": {"#demo": {"exists": ""}}}}}), context)
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            summary1 = compile_records(records, Path(first), sources)
            summary2 = compile_records(list(reversed(records)), Path(second), sources)
            self.assertEqual(summary1, summary2)
            for name in (*EXTERNAL_STORE_FILES, "manifest.json"):
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes())
            loaded = load_jsonl(Path(first) / "web.jsonl", sources)
            self.assertEqual(len(loaded), 3)

    def test_rejects_unresolved_identity_conflicts(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/external-sources.json")
        context = AdapterContext("rapid7-recog", "v3.1.29", "https://x", "BSD-2-Clause", "sha256:" + "a" * 64)
        one = parse_recog_xml('<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="same"><param pos="0" name="service.product" value="A"/></fingerprint></fingerprints>', context)
        two = parse_recog_xml('<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="same"><param pos="0" name="service.product" value="B"/></fingerprint></fingerprints>', context)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unresolved external corpus conflict"):
                compile_records(one + two, Path(tmp), sources)


if __name__ == "__main__":
    unittest.main()
