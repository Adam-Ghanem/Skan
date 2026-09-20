from __future__ import annotations

from typing import Iterable, Mapping

from tools.corpus.model import CanonicalRecord
from tools.corpus.sources import SourcePolicy


_SPECIAL = {
    "rapid7-recog": "Rapid7 Recog is used under BSD-2-Clause. Copyright 2014, Rapid7, Inc. Redistribution retains the upstream copyright and license notice.",
    "wappalyzergo": "ProjectDiscovery WappalyzerGo fingerprint data is used under the MIT License; upstream copyright and permission notice must be retained.",
    "iana-services": "IANA protocol registry metadata is used under the IANA/IETF CC0 1.0 public-domain dedication.",
    "nvd-cpe": "NIST National Vulnerability Database CPE data is public U.S. Government data. Skan acknowledges NIST/NVD and marks normalized or indexed outputs as modified data; NIST does not endorse Skan.",
}


def render_notices(
    records: Iterable[CanonicalRecord],
    sources: Mapping[str, SourcePolicy],
) -> str:
    used = sorted({item.source_id for record in records for item in record.provenance})
    lines = ["# Skan Fingerprint Corpus Third-Party Notices", ""]
    for source_id in used:
        source = sources.get(source_id)
        if source is None:
            raise ValueError(f"unknown source in attribution: {source_id}")
        if not source.attribution_required and source_id not in _SPECIAL:
            continue
        lines.extend(
            [
                f"## {source.name}",
                "",
                f"Policy/license: `{source.license_spdx_or_policy}`",
                "",
                _SPECIAL.get(source_id, f"Source: {source.homepage}"),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
