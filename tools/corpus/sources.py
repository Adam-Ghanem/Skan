from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourcePolicy:
    id: str
    name: str
    homepage: str
    source_url: str
    license_spdx_or_policy: str
    redistribution_allowed: bool
    attribution_required: bool
    approved_data_classes: tuple[str, ...]
    blocked_data_classes: tuple[str, ...]
    pinned_revision: str | None
    expected_hash: str | None
    adapter: str
    notes: str


def _require_bool(item: dict[str, Any], key: str) -> bool:
    value = item.get(key)
    if type(value) is not bool:
        raise ValueError(f"{key} must be boolean")
    return value


def _require_string(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be string")
    return value


def _require_string_list(item: dict[str, Any], key: str) -> tuple[str, ...]:
    value = item.get(key)
    if not isinstance(value, list) or any(not isinstance(entry, str) for entry in value):
        raise ValueError(f"{key} must be an array of strings")
    return tuple(value)


def _optional_string(item: dict[str, Any], key: str) -> str | None:
    value = item.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be string or null")
    return value


def validate_source_policy(source: SourcePolicy) -> list[str]:
    errors: list[str] = []
    if not source.id.strip():
        errors.append("source id is required")
    if not source.name.strip():
        errors.append(f"source {source.id}: name is required")
    if not source.license_spdx_or_policy.strip():
        errors.append(f"source {source.id}: license policy is required")
    if not source.adapter.strip():
        errors.append(f"source {source.id}: adapter is required")
    if source.expected_hash is not None:
        prefix = "sha256:"
        value = source.expected_hash
        digest = value[len(prefix) :] if value.startswith(prefix) else ""
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            errors.append(
                f"source {source.id}: expected_hash must be sha256:<64 lowercase hex chars>"
            )
    return errors


def load_source_manifest(path: Path) -> dict[str, SourcePolicy]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("source manifest root must be an object")
    schema_version = raw.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("unsupported source manifest schema_version")
    raw_sources = raw.get("sources")
    if not isinstance(raw_sources, list):
        raise ValueError("sources must be an array")

    result: dict[str, SourcePolicy] = {}
    for item in raw_sources:
        if not isinstance(item, dict):
            raise ValueError("source entry must be an object")
        source = SourcePolicy(
            id=_require_string(item, "id"),
            name=_require_string(item, "name"),
            homepage=_require_string(item, "homepage"),
            source_url=_require_string(item, "source_url"),
            license_spdx_or_policy=_require_string(item, "license_spdx_or_policy"),
            redistribution_allowed=_require_bool(item, "redistribution_allowed"),
            attribution_required=_require_bool(item, "attribution_required"),
            approved_data_classes=_require_string_list(item, "approved_data_classes"),
            blocked_data_classes=_require_string_list(item, "blocked_data_classes"),
            pinned_revision=_optional_string(item, "pinned_revision"),
            expected_hash=_optional_string(item, "expected_hash"),
            adapter=_require_string(item, "adapter"),
            notes=_require_string(item, "notes") if "notes" in item else "",
        )
        if source.id in result:
            raise ValueError(f"duplicate source id: {source.id}")
        errors = validate_source_policy(source)
        if errors:
            raise ValueError("; ".join(errors))
        result[source.id] = source
    return result
