from __future__ import annotations

import json
import re
from typing import Any, Iterable

from tools.corpus.adapters.common import AdapterContext, make_record
from tools.corpus.model import CanonicalRecord


_DIMENSIONS = (
    ("headers", "http_header"),
    ("cookies", "http_cookie"),
    ("html", "http_html"),
    ("scripts", "http_script"),
    ("scriptSrc", "http_script"),
    ("js", "http_js"),
    ("dom", "http_dom"),
    ("css", "http_css"),
    ("meta", "http_meta"),
)


def _directive_pattern(value: str) -> tuple[str, str | None]:
    parts = value.split("\\;")
    pattern = parts[0]
    version: str | None = None
    for directive in parts[1:]:
        if directive.startswith("version:"):
            raw = directive[len("version:"):]
            version = re.sub(r"\\([0-9]+)", lambda match: f"${match.group(1)}", raw)
    return pattern, version


def _entries(value: Any, dimension: str) -> Iterable[tuple[str, str | None, str]]:
    if isinstance(value, list):
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(f"Wappalyzer {dimension}[{index}] must be a string")
            yield item, None, str(index)
        return
    if isinstance(value, dict):
        for key in sorted(value):
            item = value[key]
            if dimension == "http_dom":
                if not isinstance(item, dict):
                    raise ValueError("Wappalyzer DOM rule must be an object")
                rendered = json.dumps(item, sort_keys=True, separators=(",", ":"))
                yield f"{key}\u0000{rendered}", None, key
                continue
            if dimension == "http_meta":
                values = item if isinstance(item, list) else [item]
                for index, pattern in enumerate(values):
                    if not isinstance(pattern, str):
                        raise ValueError("Wappalyzer meta pattern must be a string")
                    yield f"{key}\u0000{pattern}", None, f"{key}:{index}"
                continue
            if not isinstance(item, str):
                raise ValueError(f"Wappalyzer {dimension} pattern must be a string")
            yield f"{key}\u0000{item}", None, key
        return
    raise ValueError(f"Wappalyzer {dimension} data must be an array or object")


def parse_wappalyzer_json(text: str, context: AdapterContext) -> list[CanonicalRecord]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Wappalyzer JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("apps"), dict):
        raise ValueError("Wappalyzer JSON requires an apps object")

    records: list[CanonicalRecord] = []
    apps: dict[str, Any] = raw["apps"]
    for product in sorted(apps):
        data = apps[product]
        if not isinstance(data, dict):
            raise ValueError(f"Wappalyzer app {product} must be an object")
        cpe_raw = data.get("cpe")
        cpe = (cpe_raw,) if isinstance(cpe_raw, str) and cpe_raw.strip() else ()
        for source_key, dimension in _DIMENSIONS:
            if source_key not in data:
                continue
            for raw_expression, _, entry_id in _entries(data[source_key], dimension):
                if "\u0000" in raw_expression:
                    key, pattern_value = raw_expression.split("\u0000", 1)
                    pattern, version = _directive_pattern(pattern_value)
                    expression = key if not pattern else f"{key}\u0000{pattern}"
                    matcher_type = "exists" if not pattern else ("dom_rule" if dimension == "http_dom" else "regex")
                else:
                    pattern, version = _directive_pattern(raw_expression)
                    expression = pattern
                    matcher_type = "exists" if not pattern else ("dom_rule" if dimension == "http_dom" else "regex")
                is_existence = matcher_type == "exists"
                records.append(
                    make_record(
                        context,
                        f"{product}:{source_key}:{entry_id}",
                        "web_fingerprint",
                        transport="tcp",
                        address_family="any",
                        matcher_type=matcher_type,
                        matcher_expression=expression,
                        service="http",
                        product=product,
                        version=version,
                        cpe=cpe,
                        confidence=0.35 if is_existence else 0.50,
                        confidence_basis="weak:wappalyzer-existence" if is_existence else "medium:wappalyzer-pattern",
                        evidence_requirements=(f"evidence:{dimension}",),
                        evidence_dimension=dimension,
                        notes=(data.get("description") if isinstance(data.get("description"), str) else ""),
                    )
                )
    return sorted(records, key=lambda record: record.id)
