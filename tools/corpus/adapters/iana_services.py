from __future__ import annotations

import csv
import io

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.model import CanonicalRecord


_ALLOWED_TRANSPORTS = {"tcp", "udp", "sctp", "dccp"}


def _ports(value: str) -> tuple[int, ...]:
    text = value.strip()
    if not text:
        return ()
    if "-" in text:
        parts = text.split("-", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid port range: {value}")
        try:
            start, end = int(parts[0]), int(parts[1])
        except ValueError as exc:
            raise ValueError(f"invalid port range: {value}") from exc
        if start > end or start < 0 or end > 65535:
            raise ValueError(f"invalid port range: {value}")
        return tuple(range(start, end + 1))
    try:
        port = int(text)
    except ValueError as exc:
        raise ValueError(f"invalid port: {value}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"invalid port: {value}")
    return (port,)


def parse_iana_csv(text: str, context: AdapterContext) -> list[CanonicalRecord]:
    reader = csv.DictReader(io.StringIO(text))
    required = {"Service Name", "Port Number", "Transport Protocol"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise ValueError("IANA CSV is missing required columns")

    records: list[CanonicalRecord] = []
    for row_number, row in enumerate(reader, start=2):
        ports = _ports(row.get("Port Number", ""))
        if not ports:
            continue
        transport = (row.get("Transport Protocol") or "").strip().lower()
        if transport not in _ALLOWED_TRANSPORTS:
            if not transport:
                continue
            raise ValueError(f"unsupported IANA transport: {transport}")
        description = (row.get("Description") or "").strip()
        service = (row.get("Service Name") or "").strip().lower()
        if not service:
            service = "reserved" if "reserved" in description.lower() else "unassigned"
        assignment_notes = (row.get("Assignment Notes") or "").strip()
        notes = "; ".join(part for part in (description, assignment_notes) if part)
        for port in ports:
            records.append(
                make_record(
                    context,
                    f"row:{row_number}:port:{port}:{transport}",
                    "port_registry",
                    transport=transport,
                    address_family="any",
                    service=service,
                    ports=(port,),
                    confidence=None,
                    confidence_basis="metadata",
                    notes=notes,
                )
            )
    return sorted(records, key=lambda record: (record.ports, record.transport, record.service or "", record.id))
