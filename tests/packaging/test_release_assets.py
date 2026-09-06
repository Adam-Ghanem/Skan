#!/usr/bin/env python3
"""Release staging must not write into the container-owned package directory."""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/prepare_release_assets.sh"
PACKAGE_NAME = "skan_0.1.0-1_amd64.deb"
PAYLOAD = b"synthetic release staging fixture\n"


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "build")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "container-dist"
        self.source.mkdir()
        self.package = self.source / PACKAGE_NAME
        self.package.write_bytes(PAYLOAD)
        self.assets = self.directory / "release-assets"

    def stage(self, package=None):
        return subprocess.run(
            ["bash", str(SCRIPT), str(package or self.package), str(self.assets)],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_staged(self):
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.assets / PACKAGE_NAME).read_bytes(), PAYLOAD)
        self.assertEqual(
            (self.assets / "SHA256SUMS").read_text(),
            f"{hashlib.sha256(PAYLOAD).hexdigest()}  {PACKAGE_NAME}\n",
        )
        self.assertEqual(list(self.source.iterdir()), [self.package])
        check = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS"], cwd=self.assets,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_stages_package_and_valid_checksum_without_changing_source(self):
        self.assert_staged()

    def test_read_only_container_output_is_supported(self):
        self.source.chmod(0o555)
        self.addCleanup(self.source.chmod, 0o755)
        if self.source.stat().st_mode & 0o222:
            self.skipTest("filesystem does not enforce POSIX directory modes")
        self.assert_staged()

    def test_existing_output_is_not_overwritten(self):
        self.assets.mkdir()
        sentinel = self.assets / "SHA256SUMS"
        sentinel.write_text("existing release\n")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "existing release\n")
        self.assertFalse((self.assets / PACKAGE_NAME).exists())

    def test_missing_package_is_rejected_without_creating_output(self):
        self.package.unlink()
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.assets.exists())

    def test_unsafe_package_name_is_rejected_without_creating_output(self):
        package = self.source / "skan_unsafe\nname_amd64.deb"
        package.write_bytes(PAYLOAD)
        result = self.stage(package)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.assets.exists())


if __name__ == "__main__":
    unittest.main()
