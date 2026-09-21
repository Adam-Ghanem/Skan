from __future__ import annotations

import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any

from .model import ComparisonManifest, Endpoint, Expectation, Scenario


MAX_MANIFEST_BYTES = 1 << 20
MAX_SCENARIOS = 128
MAX_EXPECTATIONS = 4096
MAX_TEXT = 256
AUTHORIZATION = "operator-controlled-lab"
VALID_PROTOCOLS = frozenset({"tcp", "udp"})
VALID_STATES = frozenset(
    {"open", "closed", "filtered", "open|filtered", "unfiltered", "unreachable", "unknown", "error"}
)
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class ManifestError(ValueError):
    """The comparison manifest is unsafe, malformed, or unsupported."""


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ManifestError(f"non-finite JSON number is not allowed: {value}")


def _require_object(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ManifestError(f"{location} must be an object")
    return value


def _require_fields(
    value: dict[str, Any], required: set[str], optional: set[str], location: str
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ManifestError(f"{location} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ManifestError(f"{location} has unknown fields: {', '.join(sorted(unknown))}")


def _text(value: object, location: str, *, identifier: bool = False) -> str:
    if type(value) is not str or not value or len(value) > MAX_TEXT:
        raise ManifestError(f"{location} must be a non-empty bounded string")
    if identifier and IDENTIFIER.fullmatch(value) is None:
        raise ManifestError(f"{location} is not a stable identifier")
    return value


def _literal_ip(value: object, location: str) -> str:
    text = _text(value, location)
    if "%" in text:
        raise ManifestError(f"{location} must not contain an interface scope")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as error:
        raise ManifestError(f"{location} must be one literal IP address") from error


def _expectation(value: object, target: str, protocol: str, location: str) -> Expectation:
    item = _require_object(value, location)
    _require_fields(item, {"port", "state"}, {"service", "product", "version"}, location)
    port = item["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ManifestError(f"{location}.port must be an integer from 1 to 65535")
    state = _text(item["state"], f"{location}.state")
    if state not in VALID_STATES:
        raise ManifestError(f"{location}.state is unsupported")
    service = _text(item["service"], f"{location}.service") if "service" in item else None
    product = _text(item["product"], f"{location}.product") if "product" in item else None
    version = _text(item["version"], f"{location}.version") if "version" in item else None
    if service is None and (product is not None or version is not None):
        raise ManifestError(f"{location} product/version requires service ground truth")
    return Expectation(Endpoint(target, protocol, port), state, service, product, version)


def _scenario(value: object, location: str) -> Scenario:
    item = _require_object(value, location)
    _require_fields(
        item,
        {"id", "target", "protocol", "timeout_seconds", "authorization", "expectations"},
        set(),
        location,
    )
    identifier = _text(item["id"], f"{location}.id", identifier=True)
    target = _literal_ip(item["target"], f"{location}.target")
    protocol = _text(item["protocol"], f"{location}.protocol")
    if protocol not in VALID_PROTOCOLS:
        raise ManifestError(f"{location}.protocol must be tcp or udp")
    timeout = item["timeout_seconds"]
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 600:
        raise ManifestError(f"{location}.timeout_seconds must be finite and in (0, 600]")
    if item["authorization"] != AUTHORIZATION:
        raise ManifestError(f"{location}.authorization must be {AUTHORIZATION}")
    raw_expectations = item["expectations"]
    if type(raw_expectations) is not list or not raw_expectations:
        raise ManifestError(f"{location}.expectations must be a non-empty array")
    if len(raw_expectations) > MAX_EXPECTATIONS:
        raise ManifestError(f"{location}.expectations exceeds the collection limit")
    expectations = tuple(
        _expectation(entry, target, protocol, f"{location}.expectations[{index}]")
        for index, entry in enumerate(raw_expectations)
    )
    endpoints = [entry.endpoint for entry in expectations]
    if len(set(endpoints)) != len(endpoints):
        raise ManifestError(f"{location} contains duplicate endpoints")
    return Scenario(identifier, target, protocol, float(timeout), AUTHORIZATION, expectations)


def parse_manifest(raw: bytes) -> ComparisonManifest:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest exceeds the size limit")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"invalid manifest JSON: {error}") from error
    root = _require_object(document, "manifest")
    _require_fields(root, {"schema_version", "suite_id", "scenarios"}, set(), "manifest")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ManifestError("manifest.schema_version must be 1")
    suite_id = _text(root["suite_id"], "manifest.suite_id", identifier=True)
    raw_scenarios = root["scenarios"]
    if type(raw_scenarios) is not list or not raw_scenarios:
        raise ManifestError("manifest.scenarios must be a non-empty array")
    if len(raw_scenarios) > MAX_SCENARIOS:
        raise ManifestError("manifest.scenarios exceeds the collection limit")
    scenarios = tuple(
        _scenario(entry, f"manifest.scenarios[{index}]")
        for index, entry in enumerate(raw_scenarios)
    )
    identifiers = [scenario.identifier for scenario in scenarios]
    if len(set(identifiers)) != len(identifiers):
        raise ManifestError("manifest contains duplicate scenario identifiers")
    if sum(len(scenario.expectations) for scenario in scenarios) > MAX_EXPECTATIONS:
        raise ManifestError("manifest exceeds the total expectation limit")
    return ComparisonManifest(1, suite_id, scenarios)


def load_manifest(path: str | Path) -> ComparisonManifest:
    source = Path(path)
    try:
        with source.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise ManifestError(f"cannot read manifest: {error}") from error
    return parse_manifest(raw)
