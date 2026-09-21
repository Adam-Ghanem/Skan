from __future__ import annotations

from .model import Scenario


def _ports(scenario: Scenario) -> str:
    ports = sorted({expectation.port for expectation in scenario.expectations})
    if not ports:
        raise ValueError("comparison scenario has no ports")
    if scenario.protocol not in ("tcp", "udp"):
        raise ValueError("comparison scenario protocol must be tcp or udp")
    if any(expectation.endpoint.protocol != scenario.protocol for expectation in scenario.expectations):
        raise ValueError("comparison expectation protocol does not match its scenario")
    return ",".join(str(port) for port in ports)


def build_skan_command(scenario: Scenario, binary: str = "bin/skan") -> list[str]:
    ports = _ports(scenario)
    command = [binary, "scan", scenario.target, "-Pn"]
    if scenario.protocol == "tcp":
        command.extend(["-sT", "-sV", "--tcp-ports", ports])
    else:
        command.extend(["--udp-ports", ports, "--service-detect", "--transport", "linux"])
    command.extend(["--output", "json", "--no-color"])
    return command


def build_nmap_command(scenario: Scenario, binary: str = "nmap") -> list[str]:
    ports = _ports(scenario)
    scan_type = "-sT" if scenario.protocol == "tcp" else "-sU"
    prefix = "T:" if scenario.protocol == "tcp" else "U:"
    return [
        binary,
        "-n",
        "--disable-arp-ping",
        "-Pn",
        scan_type,
        "-sV",
        "-p",
        prefix + ports,
        "-oX",
        "-",
        scenario.target,
    ]
