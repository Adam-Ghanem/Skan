from __future__ import annotations

import json
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.nvd_cpe import parse_cpe23_name, parse_nvd_cpe_json
from tools.corpus.cpe_index import CpeCandidate, build_cpe_index, lookup_cpe


CTX = AdapterContext(
    source_id="nvd-cpe",
    revision="2026-09-07",
    source_url="https://services.nvd.nist.gov/rest/json/cpes/2.0",
    source_license="NIST-Public-Data",
    source_hash="sha256:" + "d" * 64,
)


class NvdCpeAdapterTests(unittest.TestCase):
    def test_parses_cpe_23_and_keeps_it_metadata_only(self) -> None:
        raw = {
            "products": [
                {"cpe": {
                    "cpeNameId": "id-1",
                    "cpeName": "cpe:2.3:a:nginx:nginx:1.25.4:update:pro:en:server:linux:x86_64:other",
                    "deprecated": False,
                    "titles": [{"title": "nginx 1.25.4", "lang": "en"}],
                    "refs": [
                        {"ref": "https://nginx.org/en/CHANGES", "type": "Change Log"},
                        {"ref": "https://nginx.org/", "type": "Vendor"},
                    ],
                }}
            ]
        }
        records = parse_nvd_cpe_json(json.dumps(raw), CTX)
        cpe = next(r for r in records if r.kind == "cpe_record")
        self.assertEqual(cpe.vendor, "nginx")
        self.assertEqual(cpe.product, "nginx")
        self.assertEqual(cpe.version, "1.25.4")
        self.assertEqual(cpe.confidence, None)
        self.assertEqual(cpe.confidence_basis, "metadata")
        self.assertIn("reference:https://nginx.org/", cpe.evidence_requirements)
        self.assertIn("reference:https://nginx.org/en/CHANGES", cpe.evidence_requirements)

        identity = parse_cpe23_name(cpe.cpe[0])
        self.assertEqual(identity.part, "a")
        self.assertEqual(identity.update, "update")
        self.assertEqual(identity.edition, "pro")
        self.assertEqual(identity.language, "en")
        self.assertEqual(identity.sw_edition, "server")
        self.assertEqual(identity.target_sw, "linux")
        self.assertEqual(identity.target_hw, "x86_64")
        self.assertEqual(identity.other, "other")

    def test_deprecated_cpe_is_preserved_as_deprecated(self) -> None:
        raw = {"products": [{"cpe": {"cpeNameId": "old", "cpeName": "cpe:2.3:a:vendor:thing:1:*:*:*:*:*:*:*", "deprecated": True}}]}
        records = parse_nvd_cpe_json(json.dumps(raw), CTX)
        self.assertTrue(all(r.status == "deprecated" for r in records))

    def test_lookup_preserves_ambiguity_as_structured_candidates(self) -> None:
        raw = {"products": [
            {"cpe": {"cpeNameId": "one", "cpeName": "cpe:2.3:a:vendor:thing:1:*:*:*:*:*:*:*", "deprecated": False}},
            {"cpe": {"cpeNameId": "two", "cpeName": "cpe:2.3:a:vendor:thing:1:update:enterprise:en:*:linux:x86:*", "deprecated": False}},
        ]}
        records = parse_nvd_cpe_json(json.dumps(raw), CTX)
        index = build_cpe_index(records)
        candidates = lookup_cpe(index, vendor="vendor", product="thing", version="1")
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(isinstance(candidate, CpeCandidate) for candidate in candidates))
        self.assertEqual([candidate.cpe for candidate in candidates], sorted(candidate.cpe for candidate in candidates))
        enterprise = next(candidate for candidate in candidates if candidate.edition == "enterprise")
        self.assertEqual(enterprise.target_sw, "linux")
        self.assertEqual(enterprise.target_hw, "x86")


if __name__ == "__main__":
    unittest.main()
