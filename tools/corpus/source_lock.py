from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class SourceLock:
    source_id: str
    revision: str
    source_url: str
    sha256: str
    adapter_version: int
    license_policy: str
    attribution: str

    def validate(self) -> None:
        errors: list[str] = []
        for name, value in (
            ("source_id", self.source_id),
            ("revision", self.revision),
            ("source_url", self.source_url),
            ("license_policy", self.license_policy),
        ):
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{name} is required")
        if len(self.sha256) != 64 or any(ch not in _HEX for ch in self.sha256):
            errors.append("sha256 must contain 64 lowercase hexadecimal characters")
        if type(self.adapter_version) is not int or self.adapter_version <= 0:
            errors.append("adapter_version must be a positive integer")
        if not isinstance(self.attribution, str):
            errors.append("attribution must be a string")
        if errors:
            raise ValueError("; ".join(errors))


def _require_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def load_source_lock(path: Path) -> SourceLock:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("source lock root must be an object")
    if raw.get("schema_version") != 1:
        raise ValueError("unsupported source lock schema_version")
    adapter_version = raw.get("adapter_version")
    if type(adapter_version) is not int:
        raise ValueError("adapter_version must be an integer")
    lock = SourceLock(
        source_id=_require_string(raw, "source_id"),
        revision=_require_string(raw, "revision"),
        source_url=_require_string(raw, "source_url"),
        sha256=_require_string(raw, "sha256"),
        adapter_version=adapter_version,
        license_policy=_require_string(raw, "license_policy"),
        attribution=_require_string(raw, "attribution"),
    )
    lock.validate()
    return lock


def verify_snapshot(path: Path, lock: SourceLock) -> None:
    lock.validate()
    if not path.is_file():
        raise ValueError(f"snapshot does not exist: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != lock.sha256:
        raise ValueError(
            f"snapshot hash mismatch for {lock.source_id}: expected {lock.sha256}, got {actual}"
        )
