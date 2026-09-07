from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tools.corpus.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class CorpusCliTests(unittest.TestCase):
    def test_stats_command_is_machine_readable(self) -> None:
        result = _run("stats", "--root", str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertIn("total_records", parsed)
        self.assertIn("detection_records", parsed)
        self.assertIn("metadata_records", parsed)
        self.assertIn("suppressed_records", parsed)
        self.assertIn("unresolved_conflicts", parsed)
        self.assertEqual(parsed["unresolved_conflicts"], 0)

    def test_exposes_complete_offline_operator_command_set(self) -> None:
        result = _run("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("verify", "import", "stats", "benchmark", "refresh-from-snapshot"):
            self.assertIn(command, result.stdout)

    def test_import_dry_run_never_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            recog = base / "recog"
            recog.mkdir()
            (recog / "ftp.xml").write_text(
                '<fingerprints matches="ftp.banner" protocol="ftp">'
                '<fingerprint pattern="^Example FTP$"><param pos="0" name="service.product" value="ExampleFTP"/></fingerprint>'
                '</fingerprints>',
                encoding="utf-8",
            )
            iana = base / "iana.csv"
            iana.write_text(
                "Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes\n"
                "example,1234,tcp,Example,,,,,,,,\n",
                encoding="utf-8",
            )
            wapp = base / "wapp.json"
            wapp.write_text(json.dumps({"apps": {"ExampleWeb": {"headers": {"server": "Example"}}}}), encoding="utf-8")
            output = base / "generated"

            result = _run(
                "import",
                "--root", str(ROOT),
                "--recog-dir", str(recog),
                "--iana-csv", str(iana),
                "--wappalyzer-json", str(wapp),
                "--output-root", str(output),
                "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertTrue(parsed["dry_run"])
            self.assertGreater(parsed["total_records"], 0)
            self.assertFalse(output.exists())

    def test_refresh_from_snapshot_fails_closed_on_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            snapshot = base / "iana.csv"
            snapshot.write_text(
                "Service Name,Port Number,Transport Protocol,Description\nexample,1234,tcp,Example\n",
                encoding="utf-8",
            )
            lock = base / "lock.json"
            lock.write_text(
                json.dumps({
                    "schema_version": 1,
                    "source_id": "iana-services",
                    "revision": "fixture",
                    "source_url": "https://www.iana.org/assignments/service-names-port-numbers/",
                    "sha256": "0" * 64,
                    "adapter_version": 1,
                    "license_policy": "CC0-1.0",
                    "attribution": "",
                }),
                encoding="utf-8",
            )
            output = base / "out.jsonl"
            result = _run(
                "refresh-from-snapshot",
                "--snapshot", str(snapshot),
                "--lock", str(lock),
                "--adapter", "iana-services",
                "--output", str(output),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("snapshot hash mismatch", result.stderr)
            self.assertFalse(output.exists())

    def test_refresh_from_snapshot_dry_run_verifies_and_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            snapshot = base / "iana.csv"
            snapshot.write_text(
                "Service Name,Port Number,Transport Protocol,Description\nexample,1234,tcp,Example\n",
                encoding="utf-8",
            )
            digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
            lock = base / "lock.json"
            lock.write_text(
                json.dumps({
                    "schema_version": 1,
                    "source_id": "iana-services",
                    "revision": "fixture",
                    "source_url": "https://www.iana.org/assignments/service-names-port-numbers/",
                    "sha256": digest,
                    "adapter_version": 1,
                    "license_policy": "CC0-1.0",
                    "attribution": "",
                }),
                encoding="utf-8",
            )
            output = base / "out.jsonl"
            result = _run(
                "refresh-from-snapshot",
                "--snapshot", str(snapshot),
                "--lock", str(lock),
                "--adapter", "iana-services",
                "--output", str(output),
                "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["source_id"], "iana-services")
            self.assertEqual(parsed["record_count"], 1)
            self.assertTrue(parsed["dry_run"])
            self.assertFalse(output.exists())

    def test_benchmark_command_is_machine_readable_and_claim_gate_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            truth = base / "truth.json"
            skan = base / "skan.json"
            nmap = base / "nmap.xml"
            metadata = base / "metadata.json"
            truth.write_text(json.dumps({
                "127.0.0.1:tcp/80": {"service": "http", "product": "Example", "version": "1.0"}
            }), encoding="utf-8")
            skan.write_text(json.dumps({
                "127.0.0.1:tcp/80": {"service": "http", "product": "Example", "version": "1.0"}
            }), encoding="utf-8")
            nmap.write_text(
                '<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/>'
                '<ports><port protocol="tcp" portid="80"><state state="open"/>'
                '<service name="http" product="Other" version="1.0"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
            metadata.write_text(json.dumps({
                "target_set": "fixture",
                "skan_version": "fixture",
                "nmap_version": "fixture",
                "skan_command": "fixture",
                "nmap_command": "fixture",
            }), encoding="utf-8")

            result = _run(
                "benchmark",
                "--truth-json", str(truth),
                "--skan-json", str(skan),
                "--nmap-xml", str(nmap),
                "--metadata-json", str(metadata),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertIn("skan", parsed["metrics"])
            self.assertIn("nmap", parsed["metrics"])
            self.assertTrue(parsed["metadata_complete"])
            self.assertTrue(parsed["better_than_nmap_gate"])


if __name__ == "__main__":
    unittest.main()
