#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import unittest

MANIFEST = Path(__file__).with_name("truth_manifest.json")

REQUIRED_STATES = {"OPEN", "CLOSED", "FILTERED", "RATE_LIMITED"}
REQUIRED_PROFILES = {
    "clean",
    "loss-1",
    "loss-5",
    "loss-10",
    "loss-20",
    "rtt-1",
    "rtt-20",
    "rtt-100",
    "rtt-300",
    "rtt-800",
    "jitter",
    "duplicate",
    "reorder",
    "burst-loss",
    "bandwidth-10mbit",
}
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


class GroundTruthManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest()

    def test_schema_and_safety_contract(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        safety = self.manifest["safety"]
        self.assertEqual(safety["authorization_env"], "SKAN_AUTHORIZED_LAB")
        self.assertEqual(safety["authorization_value"], "1")
        self.assertIs(safety["public_targets_allowed"], False)

    def test_only_documentation_addresses_are_embedded(self) -> None:
        topology = self.manifest["topology"]
        for key in ("ipv4_scanner", "ipv4_target", "ipv6_scanner", "ipv6_target"):
            interface = ipaddress.ip_interface(topology[key])
            self.assertTrue(
                any(interface.ip in network for network in DOCUMENTATION_NETWORKS),
                f"{key} must stay inside documentation address space",
            )

    def test_truth_cases_are_unique_and_explicit(self) -> None:
        cases = self.manifest["truth_cases"]
        self.assertGreaterEqual(len(cases), 9)
        identifiers: set[str] = set()
        endpoint_keys: set[tuple[str, str, int]] = set()
        observed_states: set[str] = set()

        for case in cases:
            identifier = case["id"]
            self.assertNotIn(identifier, identifiers)
            identifiers.add(identifier)

            transport = case["transport"]
            self.assertIn(transport, {"tcp", "udp"})
            port = case["port"]
            self.assertIsInstance(port, int)
            self.assertGreater(port, 0)
            self.assertLessEqual(port, 65535)

            truth = case["configured_truth"]
            self.assertIn(truth, REQUIRED_STATES)
            observed_states.add(truth)
            self.assertTrue(case["truth_source"])

            families = case["families"]
            self.assertTrue(families)
            for family in families:
                self.assertIn(family, {"ipv4", "ipv6"})
                key = (transport, family, port)
                self.assertNotIn(key, endpoint_keys)
                endpoint_keys.add(key)

        self.assertTrue({"OPEN", "CLOSED", "FILTERED"}.issubset(observed_states))

    def test_required_fault_and_rtt_profiles_exist(self) -> None:
        profiles = self.manifest["network_profiles"]
        by_id = {profile["id"]: profile for profile in profiles}
        self.assertEqual(set(by_id), REQUIRED_PROFILES)

        for loss in (1, 5, 10, 20):
            profile = by_id[f"loss-{loss}"]
            self.assertEqual(profile["kind"], "loss")
            self.assertEqual(profile["loss_percent"], float(loss))
            self.assertEqual(profile["seed"], 424242)

        for rtt in (1, 20, 100, 300, 800):
            profile = by_id[f"rtt-{rtt}"]
            self.assertEqual(profile["kind"], "rtt")
            self.assertEqual(profile["round_trip_ms"], float(rtt))

        for identifier in ("duplicate", "reorder", "burst-loss"):
            self.assertEqual(by_id[identifier]["seed"], 424242)

    def test_truth_is_independent_of_scanner_output(self) -> None:
        sources = {case["truth_source"] for case in self.manifest["truth_cases"]}
        forbidden = {"skan", "nmap", "scanner-output", "scanner"}
        self.assertFalse(sources & forbidden)
        required_evidence = set(self.manifest["evidence_required"])
        self.assertIn("listener-snapshot", required_evidence)
        self.assertIn("ipv4-firewall-snapshot", required_evidence)
        self.assertIn("ipv6-firewall-snapshot", required_evidence)
        self.assertIn("qdisc-snapshot", required_evidence)


if __name__ == "__main__":
    unittest.main()
