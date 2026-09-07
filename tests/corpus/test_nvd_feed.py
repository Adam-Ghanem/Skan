from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.corpus.nvd_feed import split_nvd_cpe_feed


class NvdFeedSplitTests(unittest.TestCase):
    def test_streams_products_into_deterministic_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "nvdcpe-2.0.json"
            products = [
                {"cpe": {"cpeNameId": f"id-{index}", "cpeName": f"cpe:2.3:a:vendor:product:{index}:*:*:*:*:*:*:*"}}
                for index in range(5)
            ]
            source.write_text(
                json.dumps({
                    "resultsPerPage": 5,
                    "startIndex": 0,
                    "totalResults": 5,
                    "format": "NVD_CPE",
                    "version": "2.0",
                    "timestamp": "2026-09-07T00:00:00.000",
                    "products": products,
                }, separators=(",", ":")),
                encoding="utf-8",
            )

            first = root / "first"
            second = root / "second"
            stats_a = split_nvd_cpe_feed(source, first, chunk_size=2)
            stats_b = split_nvd_cpe_feed(source, second, chunk_size=2)

            self.assertEqual(stats_a, {"products": 5, "chunks": 3, "chunk_size": 2})
            self.assertEqual(stats_a, stats_b)
            names = [path.name for path in sorted(first.glob("page-*.json"))]
            self.assertEqual(names, ["page-00000.json", "page-00001.json", "page-00002.json"])
            for name in names:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            self.assertEqual(
                json.loads((first / "page-00000.json").read_text(encoding="utf-8"))["products"],
                products[:2],
            )
            self.assertEqual(
                len(json.loads((first / "page-00002.json").read_text(encoding="utf-8"))["products"]),
                1,
            )

    def test_accepts_array_close_in_next_read_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "boundary.json"
            product = {"x": "12345678901234567890"}
            source.write_text(
                json.dumps({"products": [product]}, separators=(",", ":")),
                encoding="utf-8",
            )
            with patch("tools.corpus.nvd_feed._READ_SIZE", 20):
                stats = split_nvd_cpe_feed(source, root / "out", chunk_size=1)
            self.assertEqual(stats, {"products": 1, "chunks": 1, "chunk_size": 1})
            payload = json.loads((root / "out/page-00000.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["products"], [product])

    def test_rejects_missing_products_array(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "invalid.json"
            source.write_text('{"totalResults":1,"items":[]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "products array"):
                split_nvd_cpe_feed(source, root / "out", chunk_size=2)

    def test_rejects_invalid_chunk_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "feed.json"
            source.write_text('{"products":[]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "chunk_size"):
                split_nvd_cpe_feed(source, root / "out", chunk_size=0)


if __name__ == "__main__":
    unittest.main()
