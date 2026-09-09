from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit


_MAXIMUM_MANIFEST_BYTES = 256 * 1024
_MAXIMUM_SOURCES = 256
_MAXIMUM_TEXT_BYTES = 4096
_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ADAPTER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_IMMUTABLE_REVISION = re.compile(
    r"^(?:git:[0-9a-f]{40}|rfc:[1-9][0-9]*|version:[A-Za-z0-9][A-Za-z0-9._+-]{0,127})$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

_APPROVED_LICENSE_POLICIES = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "MIT",
}
_FIRST_PARTY_ID = "skan-first-party"
_FIRST_PARTY_ADAPTER = "skan_first_party"
_FIRST_PARTY_HOMEPAGE = "https://github.com/Adam-Ghanem/Skan"

_SOURCE_CLASSES = {
    "first_party",
    "standards",
    "vendor",
    "permissive_dataset",
    "private_lab",
}
_DATA_CLASSES = {
    "active_probe",
    "os_fingerprint",
    "product_vocab",
    "registry",
    "service_matcher",
    "udp_probe",
}
_ROOT_FIELDS = {"schema_version", "sources"}
_SOURCE_FIELDS = {
    "id",
    "source_class",
    "name",
    "homepage",
    "source_url",
    "license_spdx_or_policy",
    "redistribution_allowed",
    "attribution_required",
    "attribution_notice",
    "approved_data_classes",
    "blocked_data_classes",
    "pinned_revision",
    "expected_hash",
    "adapter",
    "notes",
}


class CorpusManifestError(ValueError):
    """The source manifest is malformed or violates corpus governance policy."""


@dataclass(frozen=True)
class SourcePolicy:
    id: str
    source_class: str
    name: str
    homepage: str
    source_url: str
    license_spdx_or_policy: str
    redistribution_allowed: bool
    attribution_required: bool
    attribution_notice: str | None
    approved_data_classes: tuple[str, ...]
    blocked_data_classes: tuple[str, ...]
    pinned_revision: str
    expected_hash: str | None
    adapter: str
    notes: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CorpusManifestError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], context: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        raise CorpusManifestError(f"{context}: unknown fields: {', '.join(unknown)}")
    missing = sorted(expected - set(value))
    if missing:
        raise CorpusManifestError(f"{context}: missing fields: {', '.join(missing)}")


def _string(value: dict[str, Any], key: str, context: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise CorpusManifestError(f"{context}.{key} must be a non-empty string")
    if len(item.encode("utf-8")) > _MAXIMUM_TEXT_BYTES:
        raise CorpusManifestError(f"{context}.{key} exceeds {_MAXIMUM_TEXT_BYTES} bytes")
    return item


def _optional_string(value: dict[str, Any], key: str, context: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item.strip():
        raise CorpusManifestError(f"{context}.{key} must be null or a non-empty string")
    if len(item.encode("utf-8")) > _MAXIMUM_TEXT_BYTES:
        raise CorpusManifestError(f"{context}.{key} exceeds {_MAXIMUM_TEXT_BYTES} bytes")
    return item


def _boolean(value: dict[str, Any], key: str, context: str) -> bool:
    item = value.get(key)
    if type(item) is not bool:
        raise CorpusManifestError(f"{context}.{key} must be boolean")
    return item


def _string_list(value: dict[str, Any], key: str, context: str) -> tuple[str, ...]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise CorpusManifestError(f"{context}.{key} must be an array of strings")
    result = tuple(item)
    if len(result) != len(set(result)):
        raise CorpusManifestError(f"{key} contains duplicates")
    return result


def _https_url(value: str, field: str, context: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and (port is None or 0 <= port <= 65535)
        )
    except ValueError:
        valid = False
    if not valid:
        raise CorpusManifestError(f"{context}.{field} must use https without credentials")


def _load_source(item: Any, index: int) -> SourcePolicy:
    context = f"sources[{index}]"
    if not isinstance(item, dict):
        raise CorpusManifestError(f"{context} must be an object")
    _exact_fields(item, _SOURCE_FIELDS, context)

    raw_source_id = item.get("id")
    if (
        not isinstance(raw_source_id, str)
        or not raw_source_id.strip()
        or _SOURCE_ID.fullmatch(raw_source_id) is None
    ):
        raise CorpusManifestError(f"{context}: invalid source id")
    source_id = raw_source_id
    source_class = _string(item, "source_class", context)
    if source_class not in _SOURCE_CLASSES:
        raise CorpusManifestError(f"{context}: unsupported source_class: {source_class}")
    homepage = _string(item, "homepage", context)
    source_url = _string(item, "source_url", context)
    _https_url(homepage, "homepage", context)
    _https_url(source_url, "source_url", context)

    license_policy = _string(item, "license_spdx_or_policy", context)
    if license_policy not in _APPROVED_LICENSE_POLICIES:
        raise CorpusManifestError(f"{context}: unsupported license policy")

    redistribution_allowed = _boolean(item, "redistribution_allowed", context)
    if not redistribution_allowed:
        raise CorpusManifestError(
            f"{context}.redistribution_allowed must be true"
        )

    adapter = _string(item, "adapter", context)
    if _ADAPTER_NAME.fullmatch(adapter) is None:
        raise CorpusManifestError(f"{context}: invalid adapter name")

    approved = _string_list(item, "approved_data_classes", context)
    blocked = _string_list(item, "blocked_data_classes", context)
    for data_class in approved:
        if data_class not in _DATA_CLASSES:
            raise CorpusManifestError(f"unsupported approved data class: {data_class}")
    for data_class in blocked:
        if data_class not in _DATA_CLASSES:
            raise CorpusManifestError(f"unsupported blocked data class: {data_class}")
    if set(approved) & set(blocked):
        raise CorpusManifestError("approved and blocked data classes overlap")
    if not approved:
        raise CorpusManifestError(f"{context}.approved_data_classes must not be empty")

    raw_pinned_revision = item.get("pinned_revision")
    if not isinstance(raw_pinned_revision, str) or not raw_pinned_revision.strip():
        raise CorpusManifestError(f"{context}.pinned_revision is required")
    pinned_revision = raw_pinned_revision
    if _IMMUTABLE_REVISION.fullmatch(pinned_revision) is None:
        raise CorpusManifestError(
            f"{context}.pinned_revision must identify an immutable revision"
        )
    parsed_source_url = urlsplit(source_url)
    if pinned_revision.startswith("git:"):
        pinned_sha = pinned_revision[4:]
        path_segments = tuple(
            segment for segment in parsed_source_url.path.split("/") if segment
        )
        if (
            pinned_sha not in path_segments
            or parsed_source_url.query
            or parsed_source_url.fragment
        ):
            raise CorpusManifestError(
                f"{context}: pinned git revision must be an exact URL path segment"
            )

    if source_class == "first_party":
        if (
            source_id != _FIRST_PARTY_ID
            or adapter != _FIRST_PARTY_ADAPTER
            or homepage != _FIRST_PARTY_HOMEPAGE
        ):
            raise CorpusManifestError(
                f"{context}: untrusted first_party source identity"
            )
        pinned_sha = pinned_revision.removeprefix("git:")
        expected_path = f"/Adam-Ghanem/Skan/tree/{pinned_sha}/data"
        if (
            not pinned_revision.startswith("git:")
            or parsed_source_url.netloc != "github.com"
            or parsed_source_url.path != expected_path
            or parsed_source_url.query
            or parsed_source_url.fragment
        ):
            raise CorpusManifestError(f"{context}: untrusted first_party source URL")

    expected_hash = _optional_string(item, "expected_hash", context)
    if expected_hash is not None and _SHA256.fullmatch(expected_hash) is None:
        raise CorpusManifestError(
            f"{context}.expected_hash must be sha256:<64 lowercase hex chars>"
        )
    if source_class != "first_party" and expected_hash is None:
        raise CorpusManifestError(f"{context}: external source expected_hash is required")

    attribution_required = _boolean(item, "attribution_required", context)
    attribution_notice = _optional_string(item, "attribution_notice", context)
    if attribution_required and attribution_notice is None:
        raise CorpusManifestError(f"{context}.attribution_notice is required")

    return SourcePolicy(
        id=source_id,
        source_class=source_class,
        name=_string(item, "name", context),
        homepage=homepage,
        source_url=source_url,
        license_spdx_or_policy=license_policy,
        redistribution_allowed=redistribution_allowed,
        attribution_required=attribution_required,
        attribution_notice=attribution_notice,
        approved_data_classes=approved,
        blocked_data_classes=blocked,
        pinned_revision=pinned_revision,
        expected_hash=expected_hash,
        adapter=adapter,
        notes=_string(item, "notes", context),
    )


def load_source_manifest(path: Path) -> dict[str, SourcePolicy]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise CorpusManifestError(f"cannot read source manifest: {exc}") from exc
    if len(raw_bytes) > _MAXIMUM_MANIFEST_BYTES:
        raise CorpusManifestError(
            f"source manifest exceeds {_MAXIMUM_MANIFEST_BYTES} bytes"
        )
    try:
        raw = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise CorpusManifestError("source manifest must be valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise CorpusManifestError(f"invalid source manifest JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise CorpusManifestError("source manifest root must be an object")
    _exact_fields(raw, _ROOT_FIELDS, "manifest")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise CorpusManifestError("unsupported source manifest schema_version")
    raw_sources = raw["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise CorpusManifestError("sources must be a non-empty array")
    if len(raw_sources) > _MAXIMUM_SOURCES:
        raise CorpusManifestError(f"sources exceeds {_MAXIMUM_SOURCES} entries")

    sources: dict[str, SourcePolicy] = {}
    for index, item in enumerate(raw_sources):
        source = _load_source(item, index)
        if source.id in sources:
            raise CorpusManifestError(f"duplicate source id: {source.id}")
        sources[source.id] = source
    return sources
