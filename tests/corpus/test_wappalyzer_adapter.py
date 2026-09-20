from __future__ import annotations

import json
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.wappalyzer import parse_wappalyzer_json


CTX = AdapterContext(
    source_id="wappalyzergo",
    revision="c881bf2d7f88b11b9b32e2b0fdd050e638f6b20a",
    source_url="https://github.com/projectdiscovery/wappalyzergo/blob/c881bf2d7f88b11b9b32e2b0fdd050e638f6b20a/fingerprints_data.json",
    source_license="MIT",
    source_hash="sha256:" + "c" * 64,
)


class WappalyzerAdapterTests(unittest.TestCase):
    def test_preserves_each_web_evidence_dimension(self) -> None:
        raw = {
            "apps": {
                "DemoTech": {
                    "headers": {"server": "Demo(?:/([0-9.]+))?"},
                    "cookies": {"demo_session": ""},
                    "html": ["demo-marker"],
                    "scriptSrc": ["demo\\.js"],
                    "js": {"Demo": ""},
                    "dom": {"#demo": {"exists": ""}},
                    "css": ["\\.demo-class"],
                    "meta": {"generator": ["DemoTech"]},
                    "cpe": "cpe:/a:demo:demotech",
                }
            }
        }
        records = parse_wappalyzer_json(json.dumps(raw), CTX)
        dims = {r.evidence_dimension for r in records if r.kind == "web_fingerprint"}
        self.assertEqual(
            dims,
            {"http_header", "http_cookie", "http_html", "http_script", "http_js", "http_dom", "http_css", "http_meta"},
        )
        self.assertTrue(all(r.product == "DemoTech" for r in records if r.kind == "web_fingerprint"))
        self.assertTrue(all(r.status == "imported" for r in records))

    def test_existence_patterns_are_weak_not_verified(self) -> None:
        raw = {"apps": {"Demo": {"cookies": {"demo": ""}}}}
        record = parse_wappalyzer_json(json.dumps(raw), CTX)[0]
        self.assertEqual(record.matcher_type, "exists")
        self.assertEqual(record.confidence_basis, "weak:wappalyzer-existence")
        self.assertLess(record.confidence or 1.0, 0.5)

    def test_rejects_unknown_root_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "apps"):
            parse_wappalyzer_json("{}", CTX)


if __name__ == "__main__":
    unittest.main()
