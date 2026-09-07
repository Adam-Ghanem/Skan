from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from tools.corpus.model import CanonicalRecord


CpeIndex = dict[tuple[str, str, str], tuple[str, ...]]


def _component(value: str | None) -> str:
    return (value or "*").strip().lower()


def build_cpe_index(records: Iterable[CanonicalRecord]) -> CpeIndex:
    values: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for record in records:
        if record.kind != "cpe_record":
            continue
        key = (_component(record.vendor), _component(record.product), _component(record.version))
        values[key].update(record.cpe)
    return {key: tuple(sorted(items)) for key, items in sorted(values.items())}


def lookup_cpe(
    index: CpeIndex,
    *,
    vendor: str,
    product: str,
    version: str | None,
) -> list[str]:
    key = (_component(vendor), _component(product), _component(version))
    return list(index.get(key, ()))
