from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.source_lock import SourceLock, load_source_lock, verify_snapshot


class SourceLockTests(unittest.TestCase):
    def test_round_trip_requires_complete_pinned_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recog.lock.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "source_id": "rapid7-recog",
                        "revision": "abc123",
                        "source_url": "https://github.com/rapid7/recog",
                        "sha256": "a" * 64,
                        "adapter_version": 1,
                        "license_policy": "BSD-2-Clause",
                        "attribution": "Rapid7 Recog",
                    }
                ),
                encoding="utf-8",
            )
            lock = load_source_lock(path)
            self.assertEqual(lock.source_id, "rapid7-recog")
            self.assertEqual(lock.revision, "abc123")
            self.assertEqual(lock.sha256, "a" * 64)
            self.assertEqual(lock.adapter_version, 1)

    def test_malformed_hash_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "sha256"):
            SourceLock(
                source_id="rapid7-recog",
                revision="abc123",
                source_url="https://example.invalid",
                sha256="xyz",
                adapter_version=1,
                license_policy="BSD-2-Clause",
                attribution="Rapid7 Recog",
            ).validate()

    def test_snapshot_hash_is_verified_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "snapshot.bin"
            snapshot.write_bytes(b"abc")
            lock = SourceLock(
                source_id="rapid7-recog",
                revision="abc123",
                source_url="https://example.invalid",
                sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                adapter_version=1,
                license_policy="BSD-2-Clause",
                attribution="Rapid7 Recog",
            )
            verify_snapshot(snapshot, lock)
            snapshot.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_snapshot(snapshot, lock)


if __name__ == "__main__":
    unittest.main()
