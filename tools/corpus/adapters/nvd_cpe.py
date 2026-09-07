from __future__ import annotations

import json
from typing import Any

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.model import CanonicalRecord


def _split_cpe23(value: str) -> list[str]:
    if not value.startswith("cpe:2.3:"):
        raise ValueError(f"unsupported CPE name: {value}")
    payload = value[len("cpe:2.3:"):]
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in payload:
        if escaped:
            current.append("\\" + character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    if len(fields) != 11:
        raise ValueError(f"CPE 2.3 name must have 11 components: {value}")
    return fields


def _unescape(value: str) -> str | None:
    if value in {"*", "-", ""}:
        return None
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            output.append(value[index + 1])
            index += 2
        else:
            output.append(value[index])
            index += 1
    return "".join(output)


def parse_nvd_cpe_json(text: str, context: AdapterContext) -> list[CanonicalRecord]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid NVD CPE JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("products"), list):
        raise ValueError("NVD CPE JSON requires a products array")

    records: list[CanonicalRecord] = []
    for index, item in enumerate(raw["products"]):
        if not isinstance(item, dict) or not isinstance(item.get("cpe"), dict):
            raise ValueError(f"NVD product {index} requires a cpe object")
        cpe_obj: dict[str, Any] = item["cpe"]
        cpe_name = cpe_obj.get("cpeName")
        cpe_id = cpe_obj.get("cpeNameId")
        if not isinstance(cpe_name, str) or not cpe_name:
            raise ValueError(f"NVD product {index} requires cpeName")
        if not isinstance(cpe_id, str) or not cpe_id:
            cpe_id = f"index:{index}"
        fields = _split_cpe23(cpe_name)
        vendor = _unescape(fields[1])
        product = _unescape(fields[2])
        version = _unescape(fields[3])
        if not product:
            raise ValueError(f"NVD CPE product component is required: {cpe_name}")
        deprecated = cpe_obj.get("deprecated") is True
        status = "deprecated" if deprecated else "imported"
        title = ""
        titles = cpe_obj.get("titles")
        if isinstance(titles, list):
            for title_obj in titles:
                if isinstance(title_obj, dict) and isinstance(title_obj.get("title"), str):
                    if title_obj.get("lang") in {"en", "en-US", "en_US"} or not title:
                        title = title_obj["title"]
        common = dict(
            vendor=vendor,
            product=product,
            version=version,
            confidence=None,
            confidence_basis="metadata",
            status=status,
            notes=title,
        )
        records.append(
            make_record(
                context,
                cpe_id,
                "cpe_record",
                cpe=(cpe_name,),
                **common,
            )
        )
        records.append(
            make_record(
                context,
                f"{cpe_id}:product",
                "product_record",
                **common,
            )
        )
    return sorted(records, key=lambda record: record.id)
