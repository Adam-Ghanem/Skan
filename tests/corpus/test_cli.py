from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import replace
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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
            self.assertTrue((root / "corpus" / "canonical" / "manifest.json").read_bytes())
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

    def test_compile_rejects_tampered_or_mixed_canonical_generation(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            canonical = root / "corpus" / "canonical"
            manifest = json.loads((canonical / "manifest.json").read_bytes())
            manifest["stores"]["services.jsonl"]["count"] = 99
            (canonical / "manifest.json").write_bytes(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            )
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("manifest", stderr)
            self.assertNotIn("Traceback", stderr)

    def test_manifest_input_is_bounded_and_deep_json_is_concise(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            manifest = root / "corpus" / "canonical" / "manifest.json"
            manifest.write_bytes(b" " * ((64 << 10) + 1))
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("exceeds", stderr)
            self.assertNotIn("Traceback", stderr)

            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            manifest.write_bytes(b"[" * 2000 + b"]" * 2000 + b"\n")
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("manifest", stderr)
            self.assertNotIn("Traceback", stderr)

            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            (root / "data" / "service-probes.db").write_bytes(
                (root / "data" / "service-probes.db").read_bytes().replace(b"rarity=1", b"rarity=2", 1)
            )
            real_replace = os.replace
            replacements = 0

            def fail_after_first_store(source, destination):
                nonlocal replacements
                if Path(destination).name in {*STORE_KINDS, "manifest.json"}:
                    replacements += 1
                    if replacements == 2:
                        raise OSError("synthetic publication failure")
                return real_replace(source, destination)

            with mock.patch("tools.corpus.cli.os.replace", side_effect=fail_after_first_store):
                result, stderr = invoke(main, str(root), "import-runtime")
            self.assertNotEqual(result, 0)
            self.assertNotIn("Traceback", stderr)
            result, stderr = invoke(main, str(root), "compile")
            self.assertNotEqual(result, 0)
            self.assertIn("manifest", stderr)
            self.assertNotIn("Traceback", stderr)

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
            self.assertIn("manifest", stderr)
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
            manifest_path = root / "corpus" / "canonical" / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["stores"]["active-probes.jsonl"]["sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_path.write_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
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

    def test_rejects_resolved_reparse_escape(self) -> None:
        from tools.corpus import cli

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            escaped = root / "data"
            escaped.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            with mock.patch("tools.corpus.cli._is_reparse_point", side_effect=lambda path: path == escaped), mock.patch(
                "tools.corpus.cli._resolve_existing", side_effect=lambda path: outside if path == escaped else path.resolve()
            ):
                with self.assertRaisesRegex(cli.CorpusCLIError, "reparse|escapes"):
                    cli._path_within(root.resolve(), "data/child", "data", "runtime input directory")
            with mock.patch("tools.corpus.cli._is_reparse_point", return_value=False), mock.patch(
                "tools.corpus.cli._resolve_existing", side_effect=lambda path: outside if path == escaped else path.resolve()
            ):
                with self.assertRaisesRegex(cli.CorpusCLIError, "escapes"):
                    cli._path_within(root.resolve(), "data/child", "data", "runtime input directory")

    def test_rejects_reparse_paths_at_every_cli_directory_boundary(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))

            def invoke_reparse(arguments, target):
                with mock.patch("tools.corpus.cli._is_reparse_point", side_effect=lambda path: path == target):
                    result, stderr = invoke(main, str(root), *arguments)
                self.assertNotEqual(result, 0)
                self.assertIn("reparse", stderr)
                self.assertNotIn("Traceback", stderr)

            invoke_reparse(("import-runtime", "--runtime-dir", "data"), root / "data")
            invoke_reparse(("import-runtime", "--canonical-dir", "corpus/canonical"), root / "corpus" / "canonical")
            self.assertEqual(invoke(main, str(root), "import-runtime")[0], 0)
            output = root / "build" / "corpus-runtime"
            output.mkdir(parents=True)
            invoke_reparse(("compile", "--output-dir", "build/corpus-runtime"), output)

    def test_filesystem_failures_are_concise(self) -> None:
        from tools.corpus.cli import main

        with tempfile.TemporaryDirectory(prefix="skan-cli-") as directory:
            root = make_repository(Path(directory))
            (root / "blocker").write_bytes(b"not a directory")
            result, stderr = invoke(main, str(root), "import-runtime", "--canonical-dir", "blocker/child")
            self.assertNotEqual(result, 0)
            self.assertIn("corpus:", stderr)
            self.assertNotIn("Traceback", stderr)

            with mock.patch("tools.corpus.cli.Path.iterdir", side_effect=PermissionError("denied")):
                result, stderr = invoke(main, str(root), "import-runtime")
            self.assertNotEqual(result, 0)
            self.assertIn("corpus:", stderr)
            self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
