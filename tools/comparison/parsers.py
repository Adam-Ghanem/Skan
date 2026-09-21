from __future__ import annotations

import ipaddress
import json
import math
from typing import Any
import xml.etree.ElementTree as ET

from .manifest import MAX_TEXT, VALID_PROTOCOLS, VALID_STATES
from .model import Endpoint, Observation, RunStatus, ScannerRun, StateSummary


MAX_RESULT_BYTES = 4 << 20
MAX_OBSERVATIONS = 4096


class ResultParseError(ValueError):
    """A scanner result cannot be safely normalized."""


def _duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ResultParseError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ResultParseError(f"non-finite JSON number: {value}")


def _object(value: object, location: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ResultParseError(f"{location} must be an object")
    return value


def _array(value: object, location: str) -> list[Any]:
    if type(value) is not list:
        raise ResultParseError(f"{location} must be an array")
    return value


def _text(value: object, location: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or len(value) > MAX_TEXT or (not value and not allow_empty):
        raise ResultParseError(f"{location} must be a bounded string")
    return value


def _optional_text(value: object, location: str) -> str | None:
    if value is None or value == "":
        return None
    return _text(value, location)


def _ip(value: object, location: str) -> str:
    text = _text(value, location)
    if "%" in text:
        raise ResultParseError(f"{location} cannot contain an interface scope")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as error:
        raise ResultParseError(f"{location} must be a literal IP address") from error


def _port(value: object, location: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ResultParseError(f"{location} must be an integer from 1 to 65535")
    return value


def _protocol(value: object, location: str) -> str:
    protocol = _text(value, location).lower()
    if protocol not in VALID_PROTOCOLS:
        raise ResultParseError(f"{location} is unsupported")
    return protocol


def _state(value: object, location: str) -> str:
    state = _text(value, location).lower()
    if state not in VALID_STATES:
        raise ResultParseError(f"{location} is unsupported")
    return state


def _finite_number(value: object, location: str, minimum: float = 0.0) -> float:
    if type(value) not in (int, float):
        raise ResultParseError(f"{location} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        raise ResultParseError(f"{location} must be finite and at least {minimum}")
    return number


def _bounded(raw: bytes | bytearray, kind: str) -> bytes:
    if type(raw) not in (bytes, bytearray):
        raise ResultParseError(f"{kind} result must be bytes")
    if len(raw) > MAX_RESULT_BYTES:
        raise ResultParseError(f"{kind} result exceeds the size limit")
    return bytes(raw)


def parse_skan_json(raw: bytes | bytearray) -> ScannerRun:
    data = _bounded(raw, "Skan")
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_fields,
            parse_constant=_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResultParseError(f"invalid Skan JSON: {error}") from error
    root = _object(document, "Skan result")
    for field in ("scanner", "scan", "hosts"):
        if field not in root:
            raise ResultParseError(f"Skan result missing field: {field}")
    scanner = _object(root["scanner"], "Skan scanner")
    if "name" not in scanner or "version" not in scanner:
        raise ResultParseError("Skan scanner identity is incomplete")
    name = _text(scanner["name"], "Skan scanner.name")
    version = _text(scanner["version"], "Skan scanner.version")
    scan = _object(root["scan"], "Skan scan")
    if "duration_ms" not in scan:
        raise ResultParseError("Skan scan.duration_ms is required")
    elapsed = _finite_number(scan["duration_ms"], "Skan scan.duration_ms") / 1000.0

    observations: dict[Endpoint, Observation] = {}
    services: dict[Endpoint, tuple[str | None, str | None, str | None, float | None]] = {}
    for host_index, raw_host in enumerate(_array(root["hosts"], "Skan hosts")):
        host = _object(raw_host, f"Skan hosts[{host_index}]")
        if "address" not in host or "ports" not in host or "services" not in host:
            raise ResultParseError(f"Skan hosts[{host_index}] is incomplete")
        host_address = _ip(host["address"], f"Skan hosts[{host_index}].address")
        for index, raw_port in enumerate(_array(host["ports"], f"Skan hosts[{host_index}].ports")):
            item = _object(raw_port, f"Skan port[{index}]")
            for field in ("target", "port", "protocol", "state", "reason"):
                if field not in item:
                    raise ResultParseError(f"Skan port[{index}] missing field: {field}")
            target = _ip(item["target"], f"Skan port[{index}].target")
            if target != host_address:
                raise ResultParseError("Skan port target does not match its host")
            endpoint = Endpoint(
                target,
                _protocol(item["protocol"], f"Skan port[{index}].protocol"),
                _port(item["port"], f"Skan port[{index}].port"),
            )
            if endpoint in observations:
                raise ResultParseError(f"duplicate endpoint: {endpoint}")
            observations[endpoint] = Observation(
                endpoint,
                _state(item["state"], f"Skan port[{index}].state"),
                _text(item["reason"], f"Skan port[{index}].reason", allow_empty=True),
            )
            if len(observations) > MAX_OBSERVATIONS:
                raise ResultParseError("Skan result exceeds the observation limit")
        for index, raw_service in enumerate(_array(host["services"], f"Skan hosts[{host_index}].services")):
            item = _object(raw_service, f"Skan service[{index}]")
            for field in ("target", "port", "protocol"):
                if field not in item:
                    raise ResultParseError(f"Skan service[{index}] missing field: {field}")
            endpoint = Endpoint(
                _ip(item["target"], f"Skan service[{index}].target"),
                _protocol(item["protocol"], f"Skan service[{index}].protocol"),
                _port(item["port"], f"Skan service[{index}].port"),
            )
            if endpoint in services:
                raise ResultParseError(f"duplicate service endpoint: {endpoint}")
            if endpoint not in observations:
                raise ResultParseError(f"service without a port observation: {endpoint}")
            confidence = None
            if "confidence" in item:
                confidence = _finite_number(item["confidence"], f"Skan service[{index}].confidence")
                if confidence > 1.0:
                    raise ResultParseError("Skan service confidence exceeds 1")
            services[endpoint] = (
                _optional_text(item.get("service"), f"Skan service[{index}].service"),
                _optional_text(item.get("product"), f"Skan service[{index}].product"),
                _optional_text(item.get("version"), f"Skan service[{index}].version"),
                confidence,
            )

    merged = []
    for endpoint in sorted(observations):
        item = observations[endpoint]
        evidence = services.get(endpoint, (None, None, None, None))
        merged.append(
            Observation(endpoint, item.state, item.reason, evidence[0], evidence[1], evidence[2], evidence[3])
        )
    return ScannerRun(name, version, RunStatus.COMPLETE, elapsed, tuple(merged))


def parse_nmap_xml(raw: bytes | bytearray) -> ScannerRun:
    data = _bounded(raw, "Nmap")
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ResultParseError("Nmap XML declarations and entities are not allowed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise ResultParseError(f"invalid Nmap XML: {error}") from error
    if root.tag != "nmaprun":
        raise ResultParseError("Nmap XML root must be nmaprun")
    name = _text(root.get("scanner"), "Nmap scanner")
    version = _text(root.get("version"), "Nmap version")
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("elapsed") is None:
        raise ResultParseError("Nmap runstats elapsed value is required")
    try:
        elapsed_raw = float(finished.get("elapsed", ""))
    except ValueError as error:
        raise ResultParseError("Nmap elapsed value must be numeric") from error
    elapsed = _finite_number(elapsed_raw, "Nmap elapsed")

    observations: dict[Endpoint, Observation] = {}
    state_summaries: list[StateSummary] = []
    summarized_ports = 0
    for host_index, host in enumerate(root.findall("host")):
        addresses = []
        for address in host.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6") and address.get("addr") is not None:
                addresses.append(_ip(address.get("addr"), f"Nmap host[{host_index}].address"))
        if len(addresses) != 1:
            raise ResultParseError(f"Nmap host[{host_index}] must contain exactly one IP address")
        target = addresses[0]
        for summary_index, summary_node in enumerate(host.findall("./ports/extraports")):
            state = _state(
                summary_node.get("state"),
                f"Nmap host[{host_index}].extraports[{summary_index}].state",
            )
            try:
                count = int(summary_node.get("count", ""), 10)
            except ValueError as error:
                raise ResultParseError("Nmap extraports count must be numeric") from error
            if not 1 <= count <= MAX_OBSERVATIONS:
                raise ResultParseError("Nmap extraports count exceeds the observation limit")
            reasons = summary_node.findall("extrareasons")
            reason = ""
            if len(reasons) == 1:
                reason = _text(
                    reasons[0].get("reason", ""),
                    f"Nmap host[{host_index}].extraports[{summary_index}].reason",
                    allow_empty=True,
                )
            summarized_ports += count
            if summarized_ports + len(observations) > MAX_OBSERVATIONS:
                raise ResultParseError("Nmap result exceeds the observation limit")
            state_summaries.append(StateSummary(target, state, count, reason))
        for port_index, port_node in enumerate(host.findall("./ports/port")):
            protocol = _protocol(port_node.get("protocol"), f"Nmap port[{port_index}].protocol")
            raw_port = port_node.get("portid")
            try:
                port_number = int(raw_port or "", 10)
            except ValueError as error:
                raise ResultParseError(f"Nmap port[{port_index}].portid must be numeric") from error
            endpoint = Endpoint(target, protocol, _port(port_number, f"Nmap port[{port_index}].portid"))
            if endpoint in observations:
                raise ResultParseError(f"duplicate endpoint: {endpoint}")
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") is None:
                raise ResultParseError(f"Nmap port[{port_index}] has no state")
            service_node = port_node.find("service")
            service = product = version_text = None
            confidence = None
            if service_node is not None:
                service = _optional_text(service_node.get("name"), f"Nmap port[{port_index}].service")
                product = _optional_text(service_node.get("product"), f"Nmap port[{port_index}].product")
                version_text = _optional_text(service_node.get("version"), f"Nmap port[{port_index}].version")
                if service_node.get("conf") is not None:
                    try:
                        raw_confidence = int(service_node.get("conf", ""), 10)
                    except ValueError as error:
                        raise ResultParseError("Nmap service confidence must be an integer") from error
                    if not 0 <= raw_confidence <= 10:
                        raise ResultParseError("Nmap service confidence must be from 0 to 10")
                    confidence = raw_confidence / 10.0
            observations[endpoint] = Observation(
                endpoint,
                _state(state_node.get("state"), f"Nmap port[{port_index}].state"),
                _text(state_node.get("reason", ""), f"Nmap port[{port_index}].reason", allow_empty=True),
                service,
                product,
                version_text,
                confidence,
            )
            if summarized_ports + len(observations) > MAX_OBSERVATIONS:
                raise ResultParseError("Nmap result exceeds the observation limit")
    return ScannerRun(
        name,
        version,
        RunStatus.COMPLETE,
        elapsed,
        tuple(observations[key] for key in sorted(observations)),
        state_summaries=tuple(state_summaries),
    )
