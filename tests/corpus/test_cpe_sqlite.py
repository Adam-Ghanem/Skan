from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.cpe_sqlite import build_cpe_sqlite


class CpeSqliteTests(unittest.TestCase):
    def test_builds_queryable_deterministic_product_index(self) -> None:
        context = AdapterContext("nvd-cpe", "r1", "https://nvd.nist.gov", "NIST-Public-Data", "sha256:" + "d" * 64)
        sample = {"products": [{"cpe": {
            "cpeNameId": "id",
            "cpeName": "cpe:2.3:a:nginx:nginx:1.25.4:update:enterprise:en:server:linux:x86_64:other",
            "deprecated": False,
            "refs": [{"ref": "https://nginx.org/", "type": "Vendor"}],
        }}]}
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "chunk.json"
            source.write_text(json.dumps(sample), encoding="utf-8")
            output = Path(tmp) / "skan-cpe.sqlite"
            summary = build_cpe_sqlite([source], output, context)
            self.assertEqual(summary["cpe_records"], 1)
            db = sqlite3.connect(output)
            try:
                row = db.execute(
                    "SELECT part,vendor,product,version,update_value,edition,language,sw_edition,target_sw,target_hw,other,references_json FROM cpe"
                ).fetchone()
            finally:
                db.close()
            self.assertEqual(
                row,
                (
                    "a", "nginx", "nginx", "1.25.4", "update", "enterprise", "en",
                    "server", "linux", "x86_64", "other", '["https://nginx.org/"]',
                ),
            )


if __name__ == "__main__":
    unittest.main()
