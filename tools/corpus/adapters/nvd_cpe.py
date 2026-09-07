from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.model import CanonicalRecord


@dataclass(frozen=True)
class Cpe23Identity:
    part: str | None
    vendor: str | None
    product: str | None
    version: str | None
    update: str | None
    edition: str | None
    language: str | None
    sw_edition: str | None
    target_sw: str | None
    target_hw: str | None
    other: str | None


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


def parse_cpe23_name(value: str) -> Cpe23Identity:
    fields = _split_cpe23(value)
    values = [_unescape(field) for field in fields]
    return Cpe23Identity(
        part=values[0],
        vendor=values[1],
        product=values[2],
        version=values[3],
        update=values[4],
        edition=values[5],
        language=values[6],
        sw_edition=values[7],
        target_sw=values[8],
        target_hw=values[9],
        other=values[10],
    )


def _reference_requirements(cpe_obj: dict[str, Any]) -> tuple[str, ...]:
    refs = cpe_obj.get("refs")
    if not isinstance(refs, list):
        return ()
    values: set[str] = set()
    for item in refs:
        if not isinstance(item, dict):
            continue
        ref = item.get("ref")
        if isinstance(ref, str) and ref.strip():
            values.add(f"reference:{ref.strip()}")
    return tuple(sorted(values))


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
        identity = parse_cpe23_name(cpe_name)
        deprecated = cpe_obj.get("deprecated") is True
        status = "deprecated" if deprecated else "imported"
        title = ""
        titles = cpe_obj.get("titles")
        if isinstance(titles, list):
            for title_obj in titles:
                if isinstance(title_obj, dict) and isinstance(title_obj.get("title"), str):
                    if title_obj.get("lang") in {"en", "en-US", "en_US"} or not title:
                        title = title_obj["title"]
        references = _reference_requirements(cpe_obj)
        common = dict(
            vendor=identity.vendor,
            product=identity.product,
            version=identity.version,
            confidence=None,
            confidence_basis="metadata",
            evidence_requirements=references,
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
        if identity.product is not None:
            records.append(
                make_record(
                    context,
                    f"{cpe_id}:product",
                    "product_record",
                    **common,
                )
            )
    return sorted(records, key=lambda record: record.id)
