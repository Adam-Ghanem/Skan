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
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HINT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})*$")


def _fail(path: Path, line_number: int, message: str) -> ValueError:
    return ValueError(f"{path.name}:{line_number}: {message}")


def _logical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _finish(record: CanonicalRecord) -> CanonicalRecord:
    return replace(record, id=stable_record_id(record))


def parse_udp_db(path: Path) -> list[CanonicalRecord]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read {path}: {exc}") from exc

    records: list[CanonicalRecord] = []
    names: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        content = raw_line.split("#", 1)[0].strip()
        if not content:
            continue
        tokens = content.split()
        if len(tokens) != 6 or tokens[0] != "probe":
            raise _fail(path, line_number, "expected: probe NAME PORT PROTOCOL_HINT MAX_RESPONSE_BYTES PAYLOAD_HEX")

        _, name, port_text, protocol_hint, max_response_text, payload_hex = tokens
        if _NAME_RE.fullmatch(name) is None:
            raise _fail(path, line_number, "invalid probe name")
        if name in names:
            raise _fail(path, line_number, f"duplicate probe {name}")
        names.add(name)
        if _HINT_RE.fullmatch(protocol_hint) is None:
            raise _fail(path, line_number, "invalid protocol hint")

        try:
            port = int(port_text, 10)
        except ValueError as exc:
            raise _fail(path, line_number, "port must be an integer") from exc
        if not 0 <= port <= 65535:
            raise _fail(path, line_number, "port must be within 0..65535")

        try:
            max_response_bytes = int(max_response_text, 10)
        except ValueError as exc:
            raise _fail(path, line_number, "max response bytes must be an integer") from exc
        if max_response_bytes <= 0:
            raise _fail(path, line_number, "max response bytes must be positive")

        if not payload_hex or len(payload_hex) % 2 != 0 or _HEX_RE.fullmatch(payload_hex) is None:
            raise _fail(path, line_number, "payload must be non-empty even-length hexadecimal text")
        payload_hex = payload_hex.lower()
        order = len(records)
        logical = {
            "kind": "udp_probe",
            "probe_id": name,
            "port": port,
            "protocol_hint": protocol_hint,
            "max_response_bytes": max_response_bytes,
            "payload_hex": payload_hex,
            "probe_order": order,
        }
        provenance = (
            Provenance(
                source_id=_SOURCE_ID,
                source_record_id=f"udp-probe:{name}",
                source_revision=_SOURCE_REVISION,
                source_url=_SOURCE_URL,
                source_license=_SOURCE_LICENSE,
                source_hash=_logical_hash(logical),
            ),
        )
        record = CanonicalRecord(
            id="",
            kind="udp_probe",
            transport="udp",
            address_family="any",
            probe_id=name,
            probe_payload_ref=None,
            matcher_type=None,
            matcher_expression=None,
            service=None,
            vendor=None,
            product=None,
            version=None,
            version_info=None,
            os_family=None,
            os_generation=None,
            device_type=None,
            cpe=(),
            ports=(port,),
            rarity=None,
            confidence=None,
            confidence_basis="first-party runtime udp probe",
            evidence_requirements=("response",),
            negative_constraints=(),
            provenance=provenance,
            first_imported_revision=_SOURCE_REVISION,
            last_verified_revision=_SOURCE_REVISION,
            status="verified",
            notes="",
            probe_payload_hex=payload_hex,
            protocol_hint=protocol_hint,
            max_response_bytes=max_response_bytes,
            probe_order=order,
        )
        records.append(_finish(record))

    if not records:
        raise ValueError(f"{path.name}: database contains no probes")
    return records


def emit_udp_db(records: Iterable[CanonicalRecord]) -> str:
    record_list = list(records)
    if any(record.kind != "udp_probe" for record in record_list):
        raise ValueError("udp runtime emitter accepts only udp_probe records")
    if any(record.probe_order is None for record in record_list):
        raise ValueError("udp_probe records require probe_order")

    orders = [record.probe_order for record in record_list]
    if len(orders) != len(set(orders)):
        raise ValueError("udp runtime records contain duplicate probe_order")
    ordered = sorted(record_list, key=lambda record: (record.probe_order, record.id))
    if [record.probe_order for record in ordered] != list(range(len(ordered))):
        raise ValueError("udp runtime records require contiguous probe_order starting at zero")

    names: set[str] = set()
    lines: list[str] = []
    for record in ordered:
        if record.transport != "udp" or record.probe_id is None or _NAME_RE.fullmatch(record.probe_id) is None:
            raise ValueError(f"invalid udp probe identity: {record.probe_id}")
        if record.probe_id in names:
            raise ValueError(f"duplicate udp probe {record.probe_id}")
        names.add(record.probe_id)
        if len(record.ports) != 1 or not 0 <= record.ports[0] <= 65535:
            raise ValueError(f"udp probe {record.probe_id} requires exactly one valid port")
        if record.protocol_hint is None or _HINT_RE.fullmatch(record.protocol_hint) is None:
            raise ValueError(f"udp probe {record.probe_id} has invalid protocol hint")
        if record.max_response_bytes is None or record.max_response_bytes <= 0:
            raise ValueError(f"udp probe {record.probe_id} has invalid max response bytes")
        payload = record.probe_payload_hex
        if payload is None or not payload or len(payload) % 2 != 0 or _HEX_RE.fullmatch(payload) is None:
            raise ValueError(f"udp probe {record.probe_id} has invalid payload hex")
        lines.append(
            f"probe {record.probe_id} {record.ports[0]} {record.protocol_hint} "
            f"{record.max_response_bytes} {payload.lower()}"
        )
    return "\n".join(lines) + "\n"
