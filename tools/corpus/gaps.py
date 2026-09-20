from __future__ import annotations

from typing import Mapping

from tools.corpus.benchmark import Observation


def build_gap_report(
    truth: Mapping[str, Observation],
    skan: Mapping[str, Observation],
    nmap: Mapping[str, Observation],
) -> list[dict[str, str | None]]:
    gaps: list[dict[str, str | None]] = []
    for target_id in sorted(truth):
        expected = truth[target_id]
        skan_observation = skan.get(target_id)
        nmap_observation = nmap.get(target_id)
        skan_correct = (
            skan_observation is not None
            and skan_observation.product == expected.product
            and skan_observation.service == expected.service
        )
        nmap_correct = (
            nmap_observation is not None
            and nmap_observation.product == expected.product
            and nmap_observation.service == expected.service
        )
        if skan_correct or not nmap_correct:
            continue
        gaps.append(
            {
                "target_id": target_id,
                "protocol": expected.service,
                "expected_product": expected.product,
                "expected_version": expected.version,
                "nmap_observed_product": nmap_observation.product if nmap_observation else None,
                "status": "clean-room-research-required",
            }
        )
    return gaps
