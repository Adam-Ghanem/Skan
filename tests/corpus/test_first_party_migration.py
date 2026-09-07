import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.corpus.migrate_first_party import main, migrate_first_party


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_FILES = (
    "data/service-probes.db",
    "data/udp-probes.db",
    "data/os-fingerprints.db",
    "data/os-fingerprints-v6.db",
)
GENERATED_FILES = RUNTIME_FILES + (
    "corpus/canonical/services.jsonl",
    "corpus/canonical/udp.jsonl",
    "corpus/canonical/os.jsonl",
    "corpus/canonical/products.jsonl",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FirstPartyMigrationTests(unittest.TestCase):
    def test_repository_runtime_dbs_round_trip_semantically(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            summary = migrate_first_party(ROOT, output)

            self.assertGreater(summary["service_records"], 0)
            self.assertGreater(summary["udp_records"], 0)
            self.assertGreater(summary["os_ipv4_records"], 0)
            self.assertGreater(summary["os_ipv6_records"], 0)
            self.assertEqual(summary["roundtrip_verified"], True)
            for relative in GENERATED_FILES:
                self.assertTrue((output / relative).is_file(), relative)

    def test_migration_is_byte_deterministic_across_output_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            left = Path(temp) / "left"
            right = Path(temp) / "right"
            left_summary = migrate_first_party(ROOT, left)
            right_summary = migrate_first_party(ROOT, right)
            self.assertEqual(left_summary, right_summary)
            for relative in GENERATED_FILES:
                self.assertEqual(
                    (left / relative).read_bytes(),
                    (right / relative).read_bytes(),
                    relative,
                )

    def test_check_mode_never_mutates_repository_runtime_or_canonical_files(self):
        tracked = list(RUNTIME_FILES) + [
            "corpus/canonical/services.jsonl",
            "corpus/canonical/udp.jsonl",
            "corpus/canonical/os.jsonl",
            "corpus/canonical/products.jsonl",
        ]
        before = {relative: digest(ROOT / relative) for relative in tracked}
        self.assertEqual(main(["--root", str(ROOT), "--check"]), 0)
        after = {relative: digest(ROOT / relative) for relative in tracked}
        self.assertEqual(after, before)

    def test_summary_hashes_match_generated_runtime_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            summary = migrate_first_party(ROOT, output)
            for relative in RUNTIME_FILES:
                self.assertEqual(summary["sha256"][relative], digest(output / relative))


if __name__ == "__main__":
    unittest.main()
