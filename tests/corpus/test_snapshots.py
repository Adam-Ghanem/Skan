import tempfile
import unittest
from pathlib import Path

from tools.corpus.snapshots import sha256_file, verify_snapshot


class SnapshotIntegrityTests(unittest.TestCase):
    def test_sha256_file_matches_known_vector(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(path),
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_verify_snapshot_accepts_matching_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source"
            path.write_bytes(b"abc")
            verify_snapshot(
                path,
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_verify_snapshot_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source"
            path.write_bytes(b"abc")
            with self.assertRaisesRegex(ValueError, "snapshot hash mismatch"):
                verify_snapshot(path, "sha256:" + "0" * 64)

    def test_verify_snapshot_rejects_invalid_expected_hash_format(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source"
            path.write_bytes(b"abc")
            with self.assertRaisesRegex(ValueError, "expected snapshot hash"):
                verify_snapshot(path, "md5:deadbeef")


if __name__ == "__main__":
    unittest.main()
