from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id


_SOURCE_ID = "skan-first-party"
_SOURCE_REVISION = "repository"
_SOURCE_URL = "https://github.com/Adam-Ghanem/Skan/tree/main/data"
_SOURCE_LICENSE = "MIT"
_FEATURE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_ALLOWED_FAMILIES = {"ipv4", "ipv6"}


def _fail(path: Path, line_number: int, message: str) -> ValueError:
    return ValueError(f"{path.name}:{line_number}: {message}")


def _logical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _finish(record: CanonicalRecord) -> CanonicalRecord:
    return replace(record, id=stable_record_id(record))


def _normalized_family(value: str, path: Path, line_number: int) -> str:
    normalized = value.strip().lower()
    if normalized not in _ALLOWED_FAMILIES:
        raise _fail(path, line_number, f"unsupported address family {value!r}")
    return normalized


def parse_os_db(path: Path, address_family: str) -> list[CanonicalRecord]:
    family = address_family.lower()
    if family not in _ALLOWED_FAMILIES:
        raise ValueError("address_family must be ipv4 or ipv6")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read {path}: {exc}") from exc

    raw_records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    names: set[str] = set()
    native_ids: set[str] = set()

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        if current["class"] is None:
            raise _fail(path, current["line"], "Fingerprint requires Class")
        if not current["features"]:
            raise _fail(path, current["line"], "Fingerprint requires at least one feature")
        raw_records.append(current)
        current = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        content = raw_line.split("#", 1)[0].strip()
        if not content:
            continue
        if content.startswith("Fingerprint "):
            flush()
            name = content[len("Fingerprint ") :].strip()
            if not name or _NAME_RE.fullmatch(name) is None:
                raise _fail(path, line_number, "invalid Fingerprint name")
            if name in names:
                raise _fail(path, line_number, f"duplicate Fingerprint {name}")
            names.add(name)
            current = {
                "name": name,
                "native_id": None,
                "specificity": None,
                "class": None,
                "features": {},
                "line": line_number,
                "order": len(raw_records),
            }
            continue

        if current is None:
            raise _fail(path, line_number, "directive appears before Fingerprint")

        if content.startswith("Class "):
            if current["class"] is not None:
                raise _fail(path, line_number, "duplicate Class")
            parts = [part.strip() for part in content[len("Class ") :].split("|")]
            if len(parts) != 4 or any(not part for part in parts):
                raise _fail(path, line_number, "Class requires vendor | os family | generation | device type")
            current["class"] = tuple(parts)
            continue

        key, separator, value = content.partition("=")
        if not separator or not key or not value:
            raise _fail(path, line_number, "expected KEY=VALUE or Class")
        key = key.strip()
        value = value.strip()
        if key == "ID":
            if current["native_id"] is not None:
                raise _fail(path, line_number, "duplicate ID")
            if not value:
                raise _fail(path, line_number, "ID must be non-empty")
            if value in native_ids:
                raise _fail(path, line_number, f"duplicate ID {value}")
            native_ids.add(value)
            current["native_id"] = value
        elif key == "SPECIFICITY":
            if current["specificity"] is not None:
                raise _fail(path, line_number, "duplicate SPECIFICITY")
            try:
                specificity = int(value, 10)
            except ValueError as exc:
                raise _fail(path, line_number, "SPECIFICITY must be an integer") from exc
            if specificity < 0:
                raise _fail(path, line_number, "SPECIFICITY must be non-negative")
            current["specificity"] = specificity
        elif key == "ADDRESS_FAMILY":
            declared = _normalized_family(value, path, line_number)
            if declared != family:
                raise _fail(
                    path,
                    line_number,
                    f"ADDRESS_FAMILY {value!r} does not match requested {address_family!r}",
                )
        else:
            if _FEATURE_RE.fullmatch(key) is None:
                raise _fail(path, line_number, f"invalid feature key {key!r}")
            if key in current["features"]:
                raise _fail(path, line_number, f"duplicate feature {key}")
            current["features"][key] = value

    flush()
    if not raw_records:
        raise ValueError(f"{path.name}: database contains no fingerprints")

    records: list[CanonicalRecord] = []
    for raw in raw_records:
        vendor, os_family, os_generation, device_type = raw["class"]
        features = tuple(sorted(raw["features"].items()))
        logical = {
            "kind": "os_fingerprint",
            "address_family": family,
            "fingerprint_name": raw["name"],
            "fingerprint_native_id": raw["native_id"],
            "specificity": raw["specificity"],
            "vendor": vendor,
            "os_family": os_family,
            "os_generation": os_generation,
            "device_type": device_type,
            "os_features": [list(item) for item in features],
            "probe_order": raw["order"],
        }
        provenance = (
            Provenance(
                source_id=_SOURCE_ID,
                source_record_id=f"os-fingerprint:{family}:{raw['name']}",
                source_revision=_SOURCE_REVISION,
                source_url=_SOURCE_URL,
                source_license=_SOURCE_LICENSE,
                source_hash=_logical_hash(logical),
            ),
        )
        record = CanonicalRecord(
            id="",
            kind="os_fingerprint",
            transport="none",
            address_family=family,
            probe_id=None,
            probe_payload_ref=None,
            matcher_type=None,
            matcher_expression=None,
            service=None,
            vendor=vendor,
            product=None,
            version=None,
            version_info=None,
            os_family=os_family,
            os_generation=os_generation,
            device_type=device_type,
            cpe=(),
            ports=(),
            rarity=None,
            confidence=None,
            confidence_basis="first-party runtime os fingerprint",
            evidence_requirements=("os-probe-evidence",),
            negative_constraints=(),
            provenance=provenance,
            first_imported_revision=_SOURCE_REVISION,
            last_verified_revision=_SOURCE_REVISION,
            status="verified",
            notes="",
            fingerprint_name=raw["name"],
            fingerprint_native_id=raw["native_id"],
            specificity=raw["specificity"],
            os_features=features,
            probe_order=raw["order"],
        )
        records.append(_finish(record))
    return records


def emit_os_db(records: Iterable[CanonicalRecord]) -> str:
    record_list = list(records)
    if any(record.kind != "os_fingerprint" for record in record_list):
        raise ValueError("os runtime emitter accepts only os_fingerprint records")
    if not record_list:
        return ""

    families = {record.address_family for record in record_list}
    if len(families) != 1 or next(iter(families)) not in _ALLOWED_FAMILIES:
        raise ValueError("os runtime emitter requires exactly one address family")
    family = next(iter(families))
    if any(record.probe_order is None for record in record_list):
        raise ValueError("os_fingerprint records require probe_order")
    orders = [record.probe_order for record in record_list]
    if len(orders) != len(set(orders)):
        raise ValueError("os runtime records contain duplicate probe_order")
    ordered = sorted(record_list, key=lambda record: (record.probe_order, record.id))
    if [record.probe_order for record in ordered] != list(range(len(ordered))):
        raise ValueError("os runtime records require contiguous probe_order starting at zero")

    names: set[str] = set()
    native_ids: set[str] = set()
    lines: list[str] = []
    for index, record in enumerate(ordered):
        name = record.fingerprint_name
        if name is None or _NAME_RE.fullmatch(name) is None:
            raise ValueError(f"invalid fingerprint name {name!r}")
        if name in names:
            raise ValueError(f"duplicate Fingerprint {name}")
        names.add(name)
        if not record.vendor or not record.os_family or not record.os_generation or not record.device_type:
            raise ValueError(f"fingerprint {name} has incomplete Class metadata")
        if not record.os_features:
            raise ValueError(f"fingerprint {name} has no OS features")

        lines.append(f"Fingerprint {name}")
        if record.fingerprint_native_id is not None:
            if not record.fingerprint_native_id or record.fingerprint_native_id in native_ids:
                raise ValueError(f"invalid or duplicate fingerprint native ID {record.fingerprint_native_id!r}")
            native_ids.add(record.fingerprint_native_id)
            lines.append(f"ID={record.fingerprint_native_id}")
        if record.specificity is not None:
            if record.specificity < 0:
                raise ValueError(f"fingerprint {name} has invalid specificity")
            lines.append(f"SPECIFICITY={record.specificity}")
        if family == "ipv6":
            lines.append("ADDRESS_FAMILY=IPv6")
        lines.append(
            f"Class {record.vendor} | {record.os_family} | {record.os_generation} | {record.device_type}"
        )

        seen_features: set[str] = set()
        for key, value in sorted(record.os_features, key=lambda item: item[0]):
            if _FEATURE_RE.fullmatch(key) is None or key in seen_features or value == "":
                raise ValueError(f"fingerprint {name} has invalid or duplicate feature {key!r}")
            seen_features.add(key)
            lines.append(f"{key}={value}")
        if index + 1 < len(ordered):
            lines.append("")

    return "\n".join(lines) + "\n"
