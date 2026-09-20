from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Mapping


@dataclass(frozen=True)
class Observation:
    target_id: str
    service: str | None
    product: str | None
    version: str | None
    os_family: str | None
    device_type: str | None


def parse_nmap_xml(text: str) -> dict[str, Observation]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid Nmap XML: {exc}") from exc
    observations: dict[str, Observation] = {}
    for host in root.findall("host"):
        address_node = host.find("address")
        address = address_node.get("addr") if address_node is not None else "unknown"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            protocol = port.get("protocol", "tcp")
            portid = port.get("portid", "0")
            service_node = port.find("service")
            if service_node is None:
                service = product = version = os_family = device_type = None
            else:
                service = service_node.get("name")
                product = service_node.get("product")
                version = service_node.get("version")
                os_family = service_node.get("ostype")
                device_type = service_node.get("devicetype")
            target_id = f"{address}:{protocol}/{portid}"
            observations[target_id] = Observation(
                target_id, service, product, version, os_family, device_type
            )
    return observations


def _metrics(
    truth: Mapping[str, Observation],
    observed: Mapping[str, Observation],
) -> dict[str, float]:
    truth_products = {key: value for key, value in truth.items() if value.product}
    predictions = {key: value for key, value in observed.items() if value.product}
    correct_products = sum(
        1
        for key, value in predictions.items()
        if key in truth_products and value.product == truth_products[key].product
    )
    incorrect_products = len(predictions) - correct_products
    product_precision = correct_products / len(predictions) if predictions else 1.0
    product_recall = correct_products / len(truth_products) if truth_products else 1.0
    false_positive_rate = incorrect_products / len(predictions) if predictions else 0.0

    truth_versions = {key: value for key, value in truth.items() if value.version}
    version_correct = sum(
        1
        for key, value in observed.items()
        if key in truth_versions
        and value.product == truth_versions[key].product
        and value.version == truth_versions[key].version
    )
    version_accuracy = version_correct / len(truth_versions) if truth_versions else 1.0

    truth_services = {key: value for key, value in truth.items() if value.service}
    service_correct = sum(
        1 for key, value in observed.items()
        if key in truth_services and value.service == truth_services[key].service
    )
    service_accuracy = service_correct / len(truth_services) if truth_services else 1.0
    return {
        "service_accuracy": service_accuracy,
        "product_precision": product_precision,
        "product_recall": product_recall,
        "exact_version_accuracy": version_accuracy,
        "false_positive_rate": false_positive_rate,
    }


def benchmark(
    truth: Mapping[str, Observation],
    skan: Mapping[str, Observation],
    nmap: Mapping[str, Observation],
) -> dict[str, dict[str, float]]:
    return {"skan": _metrics(truth, skan), "nmap": _metrics(truth, nmap)}


def better_than_nmap_gate(
    report: Mapping[str, Mapping[str, float]],
    *,
    metadata_complete: bool,
) -> bool:
    if not metadata_complete:
        return False
    skan = report["skan"]
    nmap = report["nmap"]
    return (
        skan["product_precision"] >= nmap["product_precision"]
        and skan["product_recall"] > nmap["product_recall"]
        and skan["false_positive_rate"] <= nmap["false_positive_rate"]
    )
