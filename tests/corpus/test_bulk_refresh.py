from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.bulk_refresh import refresh_detection_sources


class BulkRefreshTests(unittest.TestCase):
    def test_refresh_isolated_external_output_is_deterministic_and_reports_emitted_records(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            recog_files = {
                "ftp.xml": '<fingerprints matches="ftp.banner" protocol="ftp"><fingerprint pattern="Demo"><param pos="0" name="service.product" value="DemoFTP"/></fingerprint></fingerprints>',
                "empty.xml": '<fingerprints matches="ssh.banner" protocol="ssh"></fingerprints>',
            }
            recog_dirs = [tmp_path / "recog-a", tmp_path / "recog-b"]
            for recog, names in zip(
                recog_dirs,
                (tuple(recog_files), tuple(reversed(recog_files))),
                strict=True,
            ):
                recog.mkdir()
                for name in names:
                    (recog / name).write_text(recog_files[name], encoding="utf-8")
            iana = tmp_path / "iana.csv"
            iana.write_text(
                "Service Name,Port Number,Transport Protocol,Description\n"
                "ftp,21,tcp,File Transfer\n"
                "ftp,21,tcp,File Transfer\n",
                encoding="utf-8",
            )
            wapp = tmp_path / "wapp.json"
            wapp.write_text(
                json.dumps({"apps": {"DemoWeb": {"html": ["demo", "demo"]}}}),
                encoding="utf-8",
            )

            outputs = [tmp_path / "out-a", tmp_path / "out-b"]
            sentinel = b"first-party-runtime-service-rules\n"
            summaries: list[dict[str, object]] = []
            for output, recog in zip(outputs, recog_dirs, strict=True):
                canonical = output / "canonical"
                canonical.mkdir(parents=True)
                (canonical / "services.jsonl").write_bytes(sentinel)
                summaries.append(
                    refresh_detection_sources(
                        repo_root=repo_root,
                        recog_dir=recog,
                        iana_csv=iana,
                        wappalyzer_json=wapp,
                        output_root=output,
                    )
                )

            for output, summary in zip(outputs, summaries, strict=True):
                self.assertTrue((output / "external" / "manifest.json").is_file())
                self.assertTrue((output / "external" / "services.jsonl").is_file())
                self.assertTrue((output / "external" / "web.jsonl").is_file())
                self.assertTrue((output / "external" / "registry.jsonl").is_file())
                self.assertEqual((output / "canonical" / "services.jsonl").read_bytes(), sentinel)
                self.assertEqual(
                    sorted(path.name for path in (output / "canonical").iterdir()),
                    ["services.jsonl"],
                )
                self.assertEqual(summary["detection_records"], 2)
                self.assertEqual(summary["port_registry_records"], 1)
                self.assertEqual(summary["total_records"], 3)
                records_by_kind = summary["records_by_kind"]
                self.assertIsInstance(records_by_kind, dict)
                self.assertEqual(
                    summary["detection_records"],
                    records_by_kind["service_matcher"] + records_by_kind["web_fingerprint"],
                )
                self.assertEqual(summary["files"]["services.jsonl"], 1)
                self.assertEqual(summary["files"]["web.jsonl"], 1)
                self.assertEqual(summary["files"]["registry.jsonl"], 1)
                self.assertTrue((output / "THIRD_PARTY_NOTICES.md").is_file())

            def recursive_bytes(root: Path) -> dict[str, bytes]:
                return {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in sorted(root.rglob("*"))
                    if path.is_file()
                }

            self.assertEqual(recursive_bytes(outputs[0]), recursive_bytes(outputs[1]))


if __name__ == "__main__":
    unittest.main()
