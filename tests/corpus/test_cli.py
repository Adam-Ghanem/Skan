from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import replace
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.model import ActiveProbeSemantics, stable_record_id
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_FILES = (
    "service-probes.db",
    "udp-probes.db",
    "os-fingerprints.db",
    "os-fingerprints-v6.db",
)
STORE_KINDS = {
    "active-probes.jsonl": "active_probe",
    "services.jsonl": "service_matcher",
    "os.jsonl": "os_fingerprint",
    "udp.jsonl": "udp_probe",
}


def make_repository(directory: Path) -> Path:
    root = directory / "repository"
    (root / "data").mkdir(parents=True)
    (root / "corpus" / "sources").mkdir(parents=True)
    (root / "corpus" / "canonical").mkdir(parents=True)
    for name in RUNTIME_FILES:
        (root / "data" / name).write_bytes((ROOT / "data" / name).read_bytes())
    (root / "corpus" / "sources" / "sources.json").write_bytes(
        (ROOT / "corpus" / "sources" / "sources.json").read_bytes()
    )
    return root


def invoke(main, *arguments: str) -> tuple[int, str]:
    stderr = StringIO()
    with redirect_stderr(stderr):
        result = main(["--repo-root", arguments[0], *arguments[1:]])
    return result, stderr.getvalue()


class CorpusCLITests(unittest.TestCase):
    def test_import_runtime_is_deterministic_from_an_unrelated_cwd(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            previous = Path.cwd()
            try:
                os.chdir(Path(directory))
                result, stderr = invoke(main, str(root), "import-runtime")
            finally:
                os.chdir(previous)
            self.assertEqual(result, 0, stderr)
            first = {
                name: (root / "corpus" / "canonical" / name).read_bytes()
                for name in STORE_KINDS
            }
            self.assertTrue(all(first.values()))
            result, stderr = invoke(main, str(root), "import-runtime")
            self.assertEqual(result, 0, stderr)
            self.assertEqual(
                first,
                {name: (root / "corpus" / "canonical" / name).read_bytes() for name in STORE_KINDS},
            )

    def test_compile_and_verify_roundtrip_are_deterministic(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            self.assertEqual(invoke(main, str(root), "compile")[0], 0)
            output = root / "build" / "corpus-runtime"
            first = {path.name: path.read_bytes() for path in output.iterdir()}
            self.assertEqual(invoke(main, str(root), "compile")[0], 0)
            self.assertEqual(first, {path.name: path.read_bytes() for path in output.iterdir()})
            result, stderr = invoke(main, str(root), "verify-roundtrip")
            self.assertEqual(result, 0, stderr)

    def test_import_failure_preserves_canonical_stores_without_traceback(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            canonical = root / "corpus" / "canonical"
            before = {name: (canonical / name).read_bytes() for name in STORE_KINDS}
            (root / "data" / "udp-probes.db").unlink()
            result, stderr = invoke(main, str(root), "import-runtime")
            self.assertNotEqual(result, 0)
            self.assertIn("missing", stderr)
            self.assertNotIn("Traceback", stderr)
            self.assertEqual(before, {name: (canonical / name).read_bytes() for name in STORE_KINDS})

    def test_compile_rejects_partial_and_wrong_kind_canonical_inputs_without_overwrite(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            self.assertEqual(invoke(main, str(root), "compile")[0], 0)
            output = root / "build" / "corpus-runtime"
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            canonical = root / "corpus" / "canonical"
            (canonical / "services.jsonl").unlink()
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("missing", stderr)
            self.assertNotIn("Traceback", stderr)
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

            (canonical / "services.jsonl").write_bytes((canonical / "udp.jsonl").read_bytes())
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("expected kind", stderr)
            self.assertNotIn("Traceback", stderr)
            self.assertEqual(before, {path.name: path.read_bytes() for path in output.iterdir()})

    def test_verify_roundtrip_detects_a_valid_semantic_mutation(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            sources = load_source_manifest(root / "corpus" / "sources" / "sources.json")
            path = root / "corpus" / "canonical" / "active-probes.jsonl"
            records = load_jsonl(path, sources, expected_kind="active_probe")
            original = records[0]
            assert isinstance(original.body, ActiveProbeSemantics)
            changed = replace(original, body=replace(original.body, payload_hex="42"))
            changed = replace(changed, id=stable_record_id(changed))
            write_jsonl(path, (changed,) + records[1:], sources)
            result, stderr = invoke(main, str(root), "verify-roundtrip")
            self.assertNotEqual(result, 0)
            self.assertIn("semantic", stderr)
            self.assertNotIn("Traceback", stderr)

    def test_rejects_symlinked_runtime_input_without_traceback(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            target = root / "data" / "service-probes.db"
            linked = root / "data" / "udp-probes.db"
            linked.unlink()
            try:
                linked.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            result, stderr = invoke(main, str(root), "import-runtime")
            self.assertNotEqual(result, 0)
            self.assertIn("symlink", stderr)
            self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
