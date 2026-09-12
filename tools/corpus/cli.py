from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterable

from tools.corpus.compiler import CompilerError, compile_corpus, validate_runtime_graph, write_compiled_corpus
from tools.corpus.io import CorpusIOError, load_jsonl, write_jsonl
from tools.corpus.model import ActiveProbeSemantics, CanonicalRecord, OSFingerprintSemantics, ServiceMatcherSemantics, UDPProbeSemantics
from tools.corpus.runtime import ImportContext, RuntimeCorpusError, parse_os_runtime, parse_service_runtime, parse_udp_runtime
from tools.corpus.sources import CorpusManifestError, SourcePolicy, load_source_manifest


_DEFAULT_ROOT = Path(__file__).resolve().parents[2]
_RUNTIME_FILES = (
    "service-probes.db",
    "udp-probes.db",
    "os-fingerprints.db",
    "os-fingerprints-v6.db",
)
_STORE_KINDS = {
    "active-probes.jsonl": "active_probe",
    "services.jsonl": "service_matcher",
    "os.jsonl": "os_fingerprint",
    "udp.jsonl": "udp_probe",
}
_CANONICAL_MANIFEST = "manifest.json"
_ARTIFACTS = {
    "service-probes.db",
    "udp-probes.db",
    "os-fingerprints.db",
    "os-fingerprints-v6.db",
    "manifest.json",
}


class CorpusCLIError(ValueError):
    """A command-line corpus operation cannot safely continue."""


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction is not None and is_junction():
            return True
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError as exc:
        raise CorpusCLIError(f"cannot inspect path safety: {exc}") from exc


def _resolve_existing(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise CorpusCLIError(f"cannot resolve path: {exc}") from exc


def _root(value: str | None) -> Path:
    candidate = Path(value) if value is not None else _DEFAULT_ROOT
    if _is_reparse_point(candidate):
        raise CorpusCLIError("repository root must not be a symlink")
    resolved = _resolve_existing(candidate)
    if not resolved.is_dir():
        raise CorpusCLIError("repository root must be a directory")
    return resolved


def _path_within(root: Path, value: str | None, default: str, label: str) -> Path:
    candidate = Path(value) if value is not None else root / default
    if not candidate.is_absolute():
        candidate = root / candidate
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(root)
    except ValueError as exc:
        raise CorpusCLIError(f"{label} escapes the repository root") from exc
    current = root
    resolved_root = _resolve_existing(root)
    for component in relative.parts:
        current /= component
        if current.exists() and current.is_symlink():
            raise CorpusCLIError(f"{label} must not contain symlinks or reparse points")
        if current.exists():
            if _is_reparse_point(current):
                raise CorpusCLIError(f"{label} must not contain symlinks or reparse points")
            try:
                _resolve_existing(current).relative_to(resolved_root)
            except ValueError as exc:
                raise CorpusCLIError(f"{label} escapes the repository root") from exc
    return lexical


def _directory(path: Path, label: str, *, must_exist: bool) -> None:
    if not path.exists():
        if must_exist:
            raise CorpusCLIError(f"{label} is missing")
        return
    if path.is_symlink():
        raise CorpusCLIError(f"{label} must not be a symlink")
    if not path.is_dir():
        raise CorpusCLIError(f"{label} must be a directory")


def _exact_directory(path: Path, allowed: set[str], label: str, *, require_all: bool, must_exist: bool) -> None:
    _directory(path, label, must_exist=must_exist)
    if not path.exists():
        return
    entries = {item.name for item in path.iterdir()}
    for item in path.iterdir():
        if item.is_symlink():
            raise CorpusCLIError(f"{label} must not contain symlinks")
    unexpected = sorted(entries - allowed)
    if unexpected:
        raise CorpusCLIError(f"{label} contains unexpected entries: {', '.join(unexpected)}")
    required = allowed if require_all else set()
    missing = sorted(required - entries)
    if missing:
        raise CorpusCLIError(f"{label} is missing: {', '.join(missing)}")


def _source_policy(root: Path) -> SourcePolicy:
    path = _path_within(root, None, "corpus/sources/sources.json", "source manifest")
    if not path.exists() or path.is_symlink() or not path.is_file():
        raise CorpusCLIError("source manifest is missing or unsafe")
    try:
        return load_source_manifest(path)["skan-first-party"]
    except (CorpusManifestError, KeyError) as exc:
        raise CorpusCLIError(f"invalid first-party source policy: {exc}") from exc


def _read_runtime(root: Path, runtime_dir: str | None, policy: SourcePolicy) -> tuple[CanonicalRecord, ...]:
    directory = _path_within(root, runtime_dir, "data", "runtime input directory")
    _exact_directory(directory, set(_RUNTIME_FILES), "runtime input directory", require_all=True, must_exist=True)
    values: dict[str, bytes] = {}
    for name in _RUNTIME_FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise CorpusCLIError(f"runtime input {name} is missing or unsafe")
        try:
            values[name] = path.read_bytes()
        except OSError as exc:
            raise CorpusCLIError(f"cannot read runtime input {name}: {exc}") from exc
    try:
        return (
            parse_service_runtime(values["service-probes.db"], ImportContext(policy, "data/service-probes.db"))
            + parse_udp_runtime(values["udp-probes.db"], ImportContext(policy, "data/udp-probes.db"))
            + parse_os_runtime(values["os-fingerprints.db"], "ipv4", ImportContext(policy, "data/os-fingerprints.db"))
            + parse_os_runtime(values["os-fingerprints-v6.db"], "ipv6", ImportContext(policy, "data/os-fingerprints-v6.db"))
        )
    except RuntimeCorpusError as exc:
        raise CorpusCLIError(f"runtime import failed: {exc}") from exc


def _store_records(records: Iterable[CanonicalRecord]) -> dict[str, tuple[CanonicalRecord, ...]]:
    groups: dict[str, list[CanonicalRecord]] = {name: [] for name in _STORE_KINDS}
    kinds = {kind: name for name, kind in _STORE_KINDS.items()}
    for record in records:
        try:
            groups[kinds[record.kind]].append(record)
        except KeyError as exc:
            raise CorpusCLIError(f"unsupported canonical record kind: {record.kind}") from exc
    return {name: tuple(group) for name, group in groups.items()}


def _canonical_directory(root: Path, value: str | None, *, output: bool) -> Path:
    path = _path_within(root, value, "corpus/canonical", "canonical directory")
    allowed = set(_STORE_KINDS) | {_CANONICAL_MANIFEST, "README.md"}
    _exact_directory(path, allowed, "canonical directory", require_all=False, must_exist=not output)
    if path.exists():
        existing = {item.name for item in path.iterdir()} & set(_STORE_KINDS)
        required = set(_STORE_KINDS) | {_CANONICAL_MANIFEST}
        if not output and not required <= {item.name for item in path.iterdir()}:
            raise CorpusCLIError("canonical directory is missing: " + ", ".join(sorted(required - {item.name for item in path.iterdir()})))
        if existing and existing != set(_STORE_KINDS):
            raise CorpusCLIError("canonical directory is partially populated")
    return path


def _canonical_manifest(records: dict[str, tuple[CanonicalRecord, ...]], staged: dict[str, Path]) -> bytes:
    stores: dict[str, dict[str, object]] = {}
    for name, kind in _STORE_KINDS.items():
        value = staged[name].read_bytes()
        stores[name] = {
            "count": len(records[name]),
            "kind": kind,
            "sha256": "sha256:" + hashlib.sha256(value).hexdigest(),
        }
    return json.dumps({"stores": stores}, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _publish_stores(directory: Path, records: dict[str, tuple[CanonicalRecord, ...]], sources: dict[str, SourcePolicy]) -> None:
    staged: dict[str, Path] = {}
    try:
        directory.mkdir(parents=True, exist_ok=True)
        for name in _STORE_KINDS:
            descriptor, raw_temporary = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
            os.close(descriptor)
            temporary = Path(raw_temporary)
            temporary.unlink()
            write_jsonl(temporary, records[name], sources)
            staged[name] = temporary
        descriptor, raw_temporary = tempfile.mkstemp(dir=directory, prefix=f".{_CANONICAL_MANIFEST}.", suffix=".tmp")
        staged[_CANONICAL_MANIFEST] = Path(raw_temporary)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_manifest(records, staged))
            stream.flush()
            os.fsync(stream.fileno())
        for name in (*_STORE_KINDS, _CANONICAL_MANIFEST):
            os.replace(staged[name], directory / name)
            staged.pop(name)
    except (OSError, CorpusIOError) as exc:
        raise CorpusCLIError(f"cannot publish canonical stores: {exc}") from exc
    finally:
        for temporary in staged.values():
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _load_canonical(root: Path, value: str | None, sources: dict[str, SourcePolicy]) -> tuple[CanonicalRecord, ...]:
    directory = _canonical_directory(root, value, output=False)
    records: list[CanonicalRecord] = []
    try:
        manifest_path = directory / _CANONICAL_MANIFEST
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise CorpusCLIError("canonical manifest is missing or unsafe")
        manifest = json.loads(manifest_path.read_bytes())
        if not isinstance(manifest, dict) or set(manifest) != {"stores"} or not isinstance(manifest["stores"], dict) or set(manifest["stores"]) != set(_STORE_KINDS):
            raise CorpusCLIError("canonical manifest is invalid")
        for name, kind in _STORE_KINDS.items():
            path = directory / name
            if path.is_symlink():
                raise CorpusCLIError(f"canonical store {name} must not be a symlink")
            entry = manifest["stores"][name]
            if not isinstance(entry, dict) or set(entry) != {"count", "kind", "sha256"} or entry["kind"] != kind or type(entry["count"]) is not int or entry["count"] < 1 or not isinstance(entry["sha256"], str):
                raise CorpusCLIError("canonical manifest is invalid")
            value = path.read_bytes()
            if entry["sha256"] != "sha256:" + hashlib.sha256(value).hexdigest():
                raise CorpusCLIError(f"canonical manifest does not match {name}")
            loaded = load_jsonl(path, sources, expected_kind=kind)
            if len(loaded) != entry["count"]:
                raise CorpusCLIError(f"canonical manifest does not match {name}")
            records.extend(loaded)
        return validate_runtime_graph(records)
    except (UnicodeDecodeError, json.JSONDecodeError, CorpusIOError, CompilerError) as exc:
        raise CorpusCLIError(f"canonical validation failed: {exc}") from exc


def _output_directory(root: Path, value: str | None) -> Path:
    path = _path_within(root, value, "build/corpus-runtime", "compiled output directory")
    _exact_directory(path, _ARTIFACTS, "compiled output directory", require_all=False, must_exist=False)
    if path.exists():
        present = {item.name for item in path.iterdir()} & _ARTIFACTS
        if present and present != _ARTIFACTS:
            raise CorpusCLIError("compiled output directory is partially populated")
    return path


def _runtime_order(records: Iterable[CanonicalRecord]) -> tuple[str, ...]:
    records = tuple(records)
    active = sorted((record for record in records if record.kind == "active_probe"), key=lambda record: record.body.declaration_order if isinstance(record.body, ActiveProbeSemantics) else -1)
    matchers = [record for record in records if record.kind == "service_matcher"]
    service: list[CanonicalRecord] = []
    for probe in active:
        service.append(probe)
        service.extend(sorted((record for record in matchers if isinstance(record.body, ServiceMatcherSemantics) and record.body.probe_name == probe.body.probe_name), key=lambda record: record.body.rule_order if isinstance(record.body, ServiceMatcherSemantics) else -1))
    udp = sorted((record for record in records if record.kind == "udp_probe"), key=lambda record: record.body.declaration_order if isinstance(record.body, UDPProbeSemantics) else -1)
    ipv4 = sorted((record for record in records if record.kind == "os_fingerprint" and isinstance(record.body, OSFingerprintSemantics) and record.body.address_family == "ipv4"), key=lambda record: record.body.runtime_id if isinstance(record.body, OSFingerprintSemantics) else "")
    ipv6 = sorted((record for record in records if record.kind == "os_fingerprint" and isinstance(record.body, OSFingerprintSemantics) and record.body.address_family == "ipv6"), key=lambda record: record.body.runtime_id if isinstance(record.body, OSFingerprintSemantics) else "")
    return tuple(record.id for record in service + udp + ipv4 + ipv6)


def _reimport_compiled(compiled, policy: SourcePolicy) -> tuple[CanonicalRecord, ...]:
    try:
        return (
            parse_service_runtime(compiled.service_probes, ImportContext(policy, "data/service-probes.db"))
            + parse_udp_runtime(compiled.udp_probes, ImportContext(policy, "data/udp-probes.db"))
            + parse_os_runtime(compiled.ipv4_os, "ipv4", ImportContext(policy, "data/os-fingerprints.db"))
            + parse_os_runtime(compiled.ipv6_os, "ipv6", ImportContext(policy, "data/os-fingerprints-v6.db"))
        )
    except RuntimeCorpusError as exc:
        raise CorpusCLIError(f"compiled round-trip import failed: {exc}") from exc


def _import_runtime(root: Path, arguments) -> None:
    policy = _source_policy(root)
    records = _read_runtime(root, arguments.runtime_dir, policy)
    try:
        checked = validate_runtime_graph(records)
    except CompilerError as exc:
        raise CorpusCLIError(f"runtime graph validation failed: {exc}") from exc
    directory = _canonical_directory(root, arguments.canonical_dir, output=True)
    _publish_stores(directory, _store_records(checked), {policy.id: policy})


def _compile(root: Path, arguments):
    policy = _source_policy(root)
    records = _load_canonical(root, arguments.canonical_dir, {policy.id: policy})
    try:
        compiled = compile_corpus(records)
        write_compiled_corpus(_output_directory(root, arguments.output_dir), compiled)
    except CompilerError as exc:
        raise CorpusCLIError(f"compilation failed: {exc}") from exc
    return compiled


def _verify_roundtrip(root: Path, arguments) -> None:
    policy = _source_policy(root)
    canonical = _load_canonical(root, arguments.canonical_dir, {policy.id: policy})
    imported = validate_runtime_graph(_read_runtime(root, arguments.runtime_dir, policy))
    if _runtime_order(canonical) != _runtime_order(imported):
        raise CorpusCLIError("canonical corpus semantic IDs do not match runtime inputs")
    compiled = _compile(root, arguments)
    if _runtime_order(canonical) != _runtime_order(_reimport_compiled(compiled, policy)):
        raise CorpusCLIError("compiled corpus semantic IDs do not match canonical records")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.corpus.cli")
    parser.add_argument("--repo-root")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("import-runtime", "compile", "verify-roundtrip"):
        subparser = subcommands.add_parser(command)
        subparser.add_argument("--runtime-dir")
        subparser.add_argument("--canonical-dir")
        subparser.add_argument("--output-dir")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        root = _root(arguments.repo_root)
        if arguments.command == "import-runtime":
            _import_runtime(root, arguments)
        elif arguments.command == "compile":
            _compile(root, arguments)
        else:
            _verify_roundtrip(root, arguments)
    except (CorpusCLIError, CorpusIOError, CompilerError, CorpusManifestError, OSError) as exc:
        print(f"corpus: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
