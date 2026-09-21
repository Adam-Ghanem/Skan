from __future__ import annotations

import unittest

from tools.comparison.commands import build_nmap_command, build_skan_command
from tools.comparison.model import Endpoint, Expectation, Scenario


def make_scenario(protocol: str, target: str = "127.0.0.1") -> Scenario:
    ports = (53, 443) if protocol == "udp" else (80, 443)
    return Scenario(
        "services",
        target,
        protocol,
        30.0,
        "operator-controlled-lab",
        tuple(Expectation(Endpoint(target, protocol, port), "open") for port in ports),
    )


class ComparisonCommandTests(unittest.TestCase):
    def test_builds_protocol_equivalent_tcp_commands(self) -> None:
        scenario = make_scenario("tcp")
        self.assertEqual(
            build_skan_command(scenario, "/opt/Skan bin/skan"),
            [
                "/opt/Skan bin/skan",
                "scan",
                "127.0.0.1",
                "-Pn",
                "-sT",
                "-sV",
                "--tcp-ports",
                "80,443",
                "--output",
                "json",
                "--no-color",
            ],
        )
        self.assertEqual(
            build_nmap_command(scenario, "/opt/Nmap bin/nmap"),
            [
                "/opt/Nmap bin/nmap",
                "-n",
                "--disable-arp-ping",
                "-Pn",
                "-sT",
                "-sV",
                "-p",
                "T:80,443",
                "-oX",
                "-",
                "127.0.0.1",
            ],
        )

    def test_builds_protocol_equivalent_udp_commands(self) -> None:
        scenario = make_scenario("udp")
        skan = build_skan_command(scenario, "skan")
        nmap = build_nmap_command(scenario, "nmap")
        self.assertIn("--udp-ports", skan)
        self.assertIn("53,443", skan)
        self.assertIn("-sU", nmap)
        self.assertIn("U:53,443", nmap)

    def test_metacharacters_remain_single_argv_elements(self) -> None:
        target = "127.0.0.1;touch /tmp/not-run"
        scenario = make_scenario("tcp", target)
        binary = "/tmp/skan;echo not-run"
        command = build_skan_command(scenario, binary)
        self.assertEqual(command[0], binary)
        self.assertEqual(command[2], target)
        self.assertNotIn("sh", command)
        self.assertNotIn("-c", command)


if __name__ == "__main__":
    unittest.main()
