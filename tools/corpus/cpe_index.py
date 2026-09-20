from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from tools.corpus.adapters.nvd_cpe import parse_cpe23_name
from tools.corpus.model import CanonicalRecord


@dataclass(frozen=True, order=True)
class CpeCandidate:
    cpe: str
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
    references: tuple[str, ...] = ()


CpeIndex = dict[tuple[str, str, str], tuple[CpeCandidate, ...]]


def _component(value: str | None) -> str:
    return (value or "*").strip().lower()


def _references(record: CanonicalRecord) -> tuple[str, ...]:
    prefix = "reference:"
    return tuple(sorted({
        value[len(prefix):]
        for value in record.evidence_requirements
        if value.startswith(prefix) and value[len(prefix):].strip()
    }))


def build_cpe_index(records: Iterable[CanonicalRecord]) -> CpeIndex:
    values: dict[tuple[str, str, str], set[CpeCandidate]] = defaultdict(set)
    for record in records:
        if record.kind != "cpe_record":
            continue
        refs = _references(record)
        for cpe in record.cpe:
            identity = parse_cpe23_name(cpe)
            key = (
                _component(identity.vendor),
                _component(identity.product),
                _component(identity.version),
            )
            values[key].add(
                CpeCandidate(
                    cpe=cpe,
                    part=identity.part,
                    vendor=identity.vendor,
                    product=identity.product,
                    version=identity.version,
                    update=identity.update,
                    edition=identity.edition,
                    language=identity.language,
                    sw_edition=identity.sw_edition,
                    target_sw=identity.target_sw,
                    target_hw=identity.target_hw,
                    other=identity.other,
                    references=refs,
                )
            )
    return {key: tuple(sorted(items)) for key, items in sorted(values.items())}


def lookup_cpe(
    index: CpeIndex,
    *,
    vendor: str,
    product: str,
    version: str | None,
) -> list[CpeCandidate]:
    key = (_component(vendor), _component(product), _component(version))
    return list(index.get(key, ()))
