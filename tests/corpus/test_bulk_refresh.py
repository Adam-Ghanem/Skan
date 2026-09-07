from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.bulk_refresh import refresh_detection_sources


class BulkRefreshTests(unittest.TestCase):
    def test_refreshes_three_detection_sources_into_canonical_files_and_stats(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            recog = tmp_path / "recog"
            recog.mkdir()
            (recog / "ftp.xml").write_text('<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="Demo"><param pos="0" name="service.product" value="DemoFTP"/></fingerprint></fingerprints>', encoding="utf-8")
            iana = tmp_path / "iana.csv"
            iana.write_text("Service Name,Port Number,Transport Protocol,Description\nftp,21,tcp,File Transfer\n", encoding="utf-8")
            wapp = tmp_path / "wapp.json"
            wapp.write_text(json.dumps({"apps": {"DemoWeb": {"html": ["demo"]}}}), encoding="utf-8")
            output = tmp_path / "out"
            summary = refresh_detection_sources(repo_root=repo_root, recog_dir=recog, iana_csv=iana, wappalyzer_json=wapp, output_root=output)
            self.assertGreaterEqual(summary["detection_records"], 2)
            self.assertEqual(summary["port_registry_records"], 1)
            self.assertTrue((output / "canonical" / "services.jsonl").is_file())
            self.assertTrue((output / "canonical" / "web.jsonl").is_file())
            self.assertTrue((output / "canonical" / "registry.jsonl").is_file())
            self.assertTrue((output / "THIRD_PARTY_NOTICES.md").is_file())


if __name__ == "__main__":
    unittest.main()
