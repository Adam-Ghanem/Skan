from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping
import unicodedata

from .manifest import IDENTIFIER, MAX_MANIFEST_BYTES, ManifestError, parse_manifest
from .model import BenchmarkScenario, ComparisonManifest, ScannerRun
from .parsers import MAX_RESULT_BYTES, ResultParseError, parse_nmap_xml, parse_skan_json


MAX_BASELINE_BYTES = 1 << 20
MAX_CAPTURES = 128
MAX_ENVIRONMENT_FIELDS = 32
MAX_PATH = 512
MAX_TEXT = 256
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESERVED_ENVIRONMENT = frozenset(
    {"baseline_id", "benchmark_conditions", "benchmark_profiles", "execution"}
)
OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd


class BaselineError(ValueError):
    """A versioned comparison bundle is malformed or fails integrity checks."""


@dataclass(frozen=True)
class Artifact:
    path: str
    sha256: str


@dataclass(frozen=True)
class Capture:
    scenario_id: str
    profile: str
    condition: str
    skan: Artifact
    nmap: Artifact


@dataclass(frozen=True)
class VerifiedBaseline:
    identifier: str
    manifest: ComparisonManifest
    scanner_runs: Mapping[str, Mapping[str, ScannerRun]]
    environment: tuple[tuple[str, str], ...]
    benchmark_scenarios: tuple[BenchmarkScenario, ...]


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BaselineError(f"non-finite JSON number is not allowed: {value}")


def _object(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise BaselineError(f"{location} must be an object")
    return value


def _fields(value: dict[str, Any], required: set[str], location: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise BaselineError(f"{location} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise BaselineError(f"{location} has unknown fields: {', '.join(sorted(unknown))}")


def _text(value: object, location: str, *, identifier: bool = False) -> str:
    if type(value) is not str or not value or len(value) > MAX_TEXT:
        raise BaselineError(f"{location} must be a non-empty bounded string")
    if identifier and IDENTIFIER.fullmatch(value) is None:
        raise BaselineError(f"{location} is not a stable identifier")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise BaselineError(f"{location} must not contain control or format characters")
    return value


def _artifact(value: object, location: str) -> Artifact:
    item = _object(value, location)
    _fields(item, {"path", "sha256"}, location)
    raw_path = item["path"]
    if type(raw_path) is not str or not raw_path or len(raw_path) > MAX_PATH:
        raise BaselineError(f"{location}.path must be a bounded relative POSIX path")
    components = raw_path.split("/")
    pure = PurePosixPath(raw_path)
    if (
        "\\" in raw_path
        or "\x00" in raw_path
        or pure.is_absolute()
        or any(component in ("", ".", "..") for component in components)
        or str(pure) != raw_path
    ):
        raise BaselineError(f"{location}.path must be a normalized relative POSIX path")
    digest = item["sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise BaselineError(f"{location}.sha256 must be 64 lowercase hexadecimal characters")
    return Artifact(raw_path, digest)


def _capture(value: object, location: str) -> Capture:
    item = _object(value, location)
    _fields(item, {"scenario_id", "profile", "condition", "skan", "nmap"}, location)
    return Capture(
        _text(item["scenario_id"], f"{location}.scenario_id", identifier=True),
        _text(item["profile"], f"{location}.profile", identifier=True),
        _text(item["condition"], f"{location}.condition", identifier=True),
        _artifact(item["skan"], f"{location}.skan"),
        _artifact(item["nmap"], f"{location}.nmap"),
    )


def _environment(value: object) -> dict[str, str]:
    item = _object(value, "baseline.environment")
    if not item or len(item) > MAX_ENVIRONMENT_FIELDS:
        raise BaselineError("baseline.environment must contain 1 to 32 fields")
    result: dict[str, str] = {}
    for raw_key, raw_value in item.items():
        key = _text(raw_key, "baseline.environment key", identifier=True)
        if key in RESERVED_ENVIRONMENT:
            raise BaselineError(f"baseline.environment uses reserved field: {key}")
        result[key] = _text(raw_value, f"baseline.environment.{key}")
    return result


def _secure_open(root_descriptor: int, relative_path: str, location: str) -> int:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags) or not OPEN_SUPPORTS_DIR_FD:
        raise BaselineError("secure descriptor-relative artifact traversal is unavailable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    current = os.dup(root_descriptor)
    try:
        components = PurePosixPath(relative_path).parts
        for component in components[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = next_descriptor
        return os.open(components[-1], file_flags, dir_fd=current)
    except OSError as error:
        raise BaselineError(f"cannot securely open {location} inside the bundle: {error}") from error
    finally:
        os.close(current)


def _open_bundle_root(path: Path) -> tuple[int, str]:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags) or not OPEN_SUPPORTS_DIR_FD:
        raise BaselineError("secure bundle-root traversal is unavailable")
    absolute = Path(os.path.abspath(path))
    if not absolute.name:
        raise BaselineError("baseline descriptor path must name a file")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    current: int | None = None
    try:
        current = os.open(os.path.sep, directory_flags)
        for component in absolute.parent.parts[1:]:
            next_descriptor = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = next_descriptor
        return current, absolute.name
    except OSError as error:
        if current is not None:
            os.close(current)
        raise BaselineError(f"cannot securely open bundle root: {error}") from error


def _read_descriptor(root_descriptor: int, name: str) -> dict[str, Any]:
    descriptor = _secure_open(root_descriptor, name, "baseline descriptor")
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise BaselineError(f"cannot inspect baseline descriptor: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise BaselineError("baseline descriptor is not a regular file")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            raw = stream.read(MAX_BASELINE_BYTES + 1)
    except OSError as error:
        raise BaselineError(f"cannot read baseline descriptor: {error}") from error
    if len(raw) > MAX_BASELINE_BYTES:
        raise BaselineError("baseline descriptor exceeds the size limit")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"invalid baseline JSON: {error}") from error
    return _object(document, "baseline")


def _verified_bytes(
    root_descriptor: int,
    artifact: Artifact,
    location: str,
    limit: int,
    used_files: set[tuple[int, int]],
) -> bytes:
    descriptor = _secure_open(root_descriptor, artifact.path, location)
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise BaselineError(f"cannot inspect {location}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise BaselineError(f"{location} is not a regular file")
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in used_files:
        os.close(descriptor)
        raise BaselineError(f"duplicate artifact path: {artifact.path}")
    used_files.add(identity)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise BaselineError(f"cannot read {location}: {error}") from error
    if len(raw) > limit:
        raise BaselineError(f"{location} exceeds the size limit")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != artifact.sha256:
        raise BaselineError(f"{location} SHA-256 mismatch: expected {artifact.sha256}, got {actual}")
    return raw


def _load_baseline(root_descriptor: int, descriptor_name: str) -> VerifiedBaseline:
    document = _read_descriptor(root_descriptor, descriptor_name)
    _fields(
        document,
        {"schema_version", "baseline_id", "manifest", "environment", "captures"},
        "baseline",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise BaselineError("baseline.schema_version must be 1")
    identifier = _text(document["baseline_id"], "baseline.baseline_id", identifier=True)
    manifest_artifact = _artifact(document["manifest"], "baseline.manifest")
    environment = _environment(document["environment"])
    raw_captures = document["captures"]
    if type(raw_captures) is not list or not raw_captures:
        raise BaselineError("baseline.captures must be a non-empty array")
    if len(raw_captures) > MAX_CAPTURES:
        raise BaselineError("baseline.captures exceeds the collection limit")
    captures = tuple(
        _capture(value, f"baseline.captures[{index}]")
        for index, value in enumerate(raw_captures)
    )
    scenario_ids = [capture.scenario_id for capture in captures]
    if len(set(scenario_ids)) != len(scenario_ids):
        raise BaselineError("baseline contains duplicate scenario captures")

    used_files: set[tuple[int, int]] = set()
    manifest_bytes = _verified_bytes(
        root_descriptor,
        manifest_artifact,
        "baseline.manifest",
        MAX_MANIFEST_BYTES,
        used_files,
    )
    try:
        manifest = parse_manifest(manifest_bytes)
    except ManifestError as error:
        raise BaselineError(f"verified manifest is invalid: {error}") from error

    expected_ids = {scenario.identifier for scenario in manifest.scenarios}
    actual_ids = set(scenario_ids)
    missing = expected_ids - actual_ids
    unknown = actual_ids - expected_ids
    if missing:
        raise BaselineError(f"baseline is missing scenario captures: {', '.join(sorted(missing))}")
    if unknown:
        raise BaselineError(f"baseline contains unknown scenario captures: {', '.join(sorted(unknown))}")

    skan_runs: dict[str, ScannerRun] = {}
    nmap_runs: dict[str, ScannerRun] = {}
    try:
        for index, capture in enumerate(captures):
            skan_raw = _verified_bytes(
                root_descriptor,
                capture.skan,
                f"baseline.captures[{index}].skan",
                MAX_RESULT_BYTES,
                used_files,
            )
            nmap_raw = _verified_bytes(
                root_descriptor,
                capture.nmap,
                f"baseline.captures[{index}].nmap",
                MAX_RESULT_BYTES,
                used_files,
            )
            skan_runs[capture.scenario_id] = parse_skan_json(skan_raw)
            nmap_runs[capture.scenario_id] = parse_nmap_xml(nmap_raw)
    except ResultParseError as error:
        raise BaselineError(f"verified scanner capture is invalid: {error}") from error

    environment.update(
        {
            "baseline_id": identifier,
            "benchmark_conditions": ",".join(sorted({item.condition for item in captures})),
            "benchmark_profiles": ",".join(sorted({item.profile for item in captures})),
            "execution": "offline-versioned-baseline",
        }
    )
    scanner_runs: Mapping[str, Mapping[str, ScannerRun]] = MappingProxyType(
        {
            "skan": MappingProxyType(skan_runs),
            "nmap": MappingProxyType(nmap_runs),
        }
    )
    benchmark_scenarios = tuple(
        sorted(
            BenchmarkScenario(item.scenario_id, item.profile, item.condition)
            for item in captures
        )
    )
    return VerifiedBaseline(
        identifier,
        manifest,
        scanner_runs,
        tuple(sorted(environment.items())),
        benchmark_scenarios,
    )


def load_baseline(path: str | Path) -> VerifiedBaseline:
    root_descriptor, descriptor_name = _open_bundle_root(Path(path))
    try:
        return _load_baseline(root_descriptor, descriptor_name)
    finally:
        os.close(root_descriptor)
