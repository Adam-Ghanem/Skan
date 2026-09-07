from __future__ import annotations

import xml.etree.ElementTree as ET

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.model import CanonicalRecord


_ALLOWED_FLAGS = {"REG_ICASE", "REG_DOT_NEWLINE", "REG_MULTILINE"}


def _flags(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    unknown = sorted(set(values) - _ALLOWED_FLAGS)
    if unknown:
        raise ValueError(f"unsupported Recog regex flag: {unknown[0]}")
    return values


def _param_value(element: ET.Element) -> str | None:
    literal = element.get("value")
    if literal is not None:
        return literal
    raw_pos = element.get("pos", "0")
    try:
        pos = int(raw_pos)
    except ValueError as exc:
        raise ValueError(f"invalid Recog param pos: {raw_pos}") from exc
    if pos <= 0:
        return None
    return f"${pos}"


def _evidence_dimension(matches: str) -> str:
    value = matches.lower()
    if value.startswith("http_header.") or value in {"http.server", "http_servers"}:
        return "http_header"
    if "cookie" in value:
        return "http_cookie"
    if "html" in value or "title" in value or "favicon" in value:
        return "http_html"
    if value.startswith("http_") or value.startswith("http."):
        return "http_header"
    return "banner"


def _apply_template(value: str | None, version: str | None) -> str | None:
    if value is None:
        return None
    if version is not None:
        value = value.replace("{service.version}", version)
    return value


def parse_recog_xml(
    text: str,
    context: AdapterContext,
    *,
    source_path: str = "recog.xml",
) -> list[CanonicalRecord]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid Recog XML: {exc}") from exc
    if root.tag != "fingerprints":
        raise ValueError("Recog root must be <fingerprints>")

    matches = (root.get("matches") or "").strip()
    protocol = (root.get("protocol") or "").strip().lower()
    if not matches:
        raise ValueError("Recog fingerprints require matches")
    if not protocol:
        raise ValueError("Recog fingerprints require protocol")
    preference = root.get("preference")

    records: list[CanonicalRecord] = []
    for index, fingerprint in enumerate(root.findall("fingerprint"), start=1):
        pattern = fingerprint.get("pattern")
        if not pattern:
            raise ValueError(f"Recog fingerprint {index} requires pattern")
        flags = _flags(fingerprint.get("flags"))
        params: dict[str, str] = {}
        for param in fingerprint.findall("param"):
            name = (param.get("name") or "").strip()
            if not name:
                raise ValueError(f"Recog fingerprint {index} has param without name")
            value = _param_value(param)
            if value is not None:
                params[name] = value

        vendor = params.get("service.vendor")
        product = params.get("service.product") or params.get("service.family")
        version = params.get("service.version")
        os_family = params.get("os.family")
        device_type = params.get("hw.device") or params.get("device.type")
        cpe_value = _apply_template(params.get("service.cpe23"), version)
        cpe = (cpe_value,) if cpe_value else ()
        description = " ".join(
            part.strip()
            for part in (fingerprint.findtext("description") or "", f"Recog preference={preference}" if preference else "")
            if part.strip()
        )
        requirements = [f"evidence:{matches}"]
        requirements.extend(f"regex_flag:{flag}" for flag in flags)
        source_id = f"{source_path}:{index}"
        dimension = _evidence_dimension(matches)

        if dimension.startswith("http_"):
            record = make_record(
                context,
                source_id,
                "web_fingerprint",
                transport="tcp",
                address_family="any",
                matcher_type="regex",
                matcher_expression=pattern,
                service="http",
                vendor=vendor,
                product=product,
                version=version,
                os_family=os_family,
                device_type=device_type,
                cpe=cpe,
                confidence=0.55,
                confidence_basis="medium:recog-passive",
                evidence_requirements=tuple(requirements),
                evidence_dimension=dimension,
                notes=description,
            )
        else:
            transport = "udp" if protocol in {"dns", "ntp", "snmp"} else "tcp"
            record = make_record(
                context,
                source_id,
                "service_matcher",
                transport=transport,
                address_family="any",
                probe_id=f"passive:{matches}",
                matcher_type="regex",
                matcher_expression=pattern,
                service=protocol,
                vendor=vendor,
                product=product,
                version=version,
                os_family=os_family,
                device_type=device_type,
                cpe=cpe,
                confidence=0.55,
                confidence_basis="medium:recog-passive",
                evidence_requirements=tuple(requirements),
                match_strength="hard",
                notes=description,
            )
        records.append(record)
    return records
