from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.wappalyzer import parse_wappalyzer_json
from tools.corpus.compile_external import compile_records
from tools.corpus.io import load_jsonl
from tools.corpus.sources import load_source_manifest


class ExternalCompilerTests(unittest.TestCase):
    def test_groups_valid_records_deterministically_and_accepts_web_dimensions(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/sources.json")
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
            for name in ("web.jsonl", "devices.jsonl", "registry.jsonl", "cpe.jsonl"):
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes())
            loaded = load_jsonl(Path(first) / "web.jsonl", sources)
            self.assertEqual(len(loaded), 3)

    def test_rejects_unresolved_identity_conflicts(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/sources.json")
        context = AdapterContext("rapid7-recog", "v3.1.29", "https://x", "BSD-2-Clause", "sha256:" + "a" * 64)
        from tools.corpus.adapters.recog import parse_recog_xml
        one = parse_recog_xml('<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="same"><param pos="0" name="service.product" value="A"/></fingerprint></fingerprints>', context)
        two = parse_recog_xml('<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="same"><param pos="0" name="service.product" value="B"/></fingerprint></fingerprints>', context)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "unresolved external corpus conflict"):
                compile_records(one + two, Path(tmp), sources)


if __name__ == "__main__":
    unittest.main()
