#!/usr/bin/env python3
"""ACK acceptance for the explicitly provisioned CI namespace, never public targets."""

import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def nmap_states(xml, requested_ports):
    document = ET.fromstring(xml)
    states = {int(port.attrib["portid"]): port.find("state").attrib["state"].upper()
              for port in document.findall("./host/ports/port")}
    missing = set(requested_ports) - states.keys()
    summaries = document.findall("./host/ports/extraports")
    if missing:
        # Nmap can summarize ignored states instead of emitting individual port rows.
        # Only one exact-count state summary permits an unambiguous reconstruction.
        assert len(summaries) == 1 and int(summaries[0].attrib["count"]) == len(missing), xml
        states.update({port: summaries[0].attrib["state"].upper() for port in missing})
    assert states.keys() == set(requested_ports), xml
    return states


def main():
    if os.environ.get("SKAN_AUTHORIZED_LAB") != "1":
        raise SystemExit("Refusing raw tests: SKAN_AUTHORIZED_LAB=1 is required")
    root = Path(__file__).resolve().parents[3]
    evidence = root / "validation_runs" / "ack"
    evidence.mkdir(parents=True, exist_ok=True)
    binary = root / "bin" / "skan"
    for family, target, ports in (
        ("ipv4", "192.0.2.2", "8080,8082,8084,8085"),
        ("ipv6", "2001:db8:29::2", "8081,8083,8084,8085"),
    ):
        flags = ["-6"] if family == "ipv6" else ["-4"]
        result = subprocess.run(
            [str(binary), *flags, "-sA", "-Pn", "--interface", "skan-lab", "-p", ports,
             "--timeout-ms", "500", "--retries", "0", "--output", "json", target],
            capture_output=True, text=True, timeout=30, check=False,
        )
        (evidence / f"{family}-skan.json").write_text(result.stdout, encoding="utf-8")
        (evidence / f"{family}-skan.stderr").write_text(result.stderr, encoding="utf-8")
        assert result.returncode == 0, (result.returncode, result.stderr)
        report = json.loads(result.stdout)
        observed = {port["port"]: (port["state"], port["reason"], port["probe"])
                    for host in report["hosts"] for port in host["ports"]}
        numbers = [int(port) for port in ports.split(",")]
        expected = {port: ("UNFILTERED", "ACK_RST", "ack") for port in numbers[:2]}
        expected[8084] = ("FILTERED", "ACK_TIMEOUT", "ack")
        expected[8085] = ("FILTERED", "ICMP_NETWORK_UNREACHABLE", "ack")
        assert observed == expected, (family, observed, result.stderr)

        # Nmap is an external lab comparator only; Skan never invokes it.
        comparator = subprocess.run(
            ["nmap", *(["-6"] if family == "ipv6" else []), "-n", "-Pn", "-sA",
             "-e", "skan-lab", "-p", ports, "--max-retries", "0", "-oX", "-", target],
            capture_output=True, text=True, timeout=30, check=False,
        )
        (evidence / f"{family}-nmap.xml").write_text(comparator.stdout, encoding="utf-8")
        (evidence / f"{family}-nmap.stderr").write_text(comparator.stderr, encoding="utf-8")
        assert comparator.returncode == 0, (comparator.returncode, comparator.stderr)
        states = nmap_states(comparator.stdout, numbers)
        assert states == {port: value[0] for port, value in expected.items()}, (family, states)
        print(f"{family}: ACK reset, silent drop, ICMP reject, and Nmap state comparison passed")


if __name__ == "__main__":
    main()
