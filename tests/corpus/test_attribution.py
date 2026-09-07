from __future__ import annotations

from pathlib import Path
import unittest

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.attribution import render_notices
from tools.corpus.sources import load_source_manifest


class AttributionTests(unittest.TestCase):
    def test_renders_only_used_external_sources_with_required_policy(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = load_source_manifest(root / "corpus/sources/sources.json")
        recog = AdapterContext("rapid7-recog", "v3.1.29", "https://x", "BSD-2-Clause", "sha256:" + "a" * 64)
        nvd = AdapterContext("nvd-cpe", "2026-09-07", "https://nvd.nist.gov", "NIST-Public-Data", "sha256:" + "d" * 64)
        records = [
            make_record(recog, "1", "product_record", product="A", confidence_basis="metadata"),
            make_record(nvd, "2", "cpe_record", product="B", cpe=("cpe:2.3:a:v:b:*:*:*:*:*:*:*:*",), confidence_basis="metadata"),
        ]
        rendered = render_notices(records, sources)
        self.assertIn("Rapid7 Recog", rendered)
        self.assertIn("BSD-2-Clause", rendered)
        self.assertIn("NIST", rendered)
        self.assertIn("modified", rendered.lower())
        self.assertNotIn("Nmap local comparator", rendered)


if __name__ == "__main__":
    unittest.main()
