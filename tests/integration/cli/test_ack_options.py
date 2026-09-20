#!/usr/bin/env python3
"""ACK CLI policy; loopback only, including when testing broken transport selection."""

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SKAN = os.environ.get("SKAN_BIN", str(ROOT / "bin/skan"))


class AckOptionTests(unittest.TestCase):
    def invoke(self, options):
        return subprocess.run(
            [SKAN, *options, "-p", "80", "--timeout-ms", "10", "--retries", "0",
             "--output", "json", "127.0.0.1"],
            cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
        )

    def test_explicit_offline_transport_is_preserved_in_either_order(self):
        for options in (
            ["-sA", "--transport", "offline"],
            ["--transport", "offline", "-sA"],
            ["--method", "ack", "--transport", "offline"],
            ["--transport", "offline", "--method", "ack"],
        ):
            with self.subTest(options=options):
                result = self.invoke(options)
                self.assertEqual(result.returncode, 0, result.stderr)
                port = json.loads(result.stdout)["hosts"][0]["ports"][0]
                self.assertEqual(port["probe"], "ack")
                self.assertEqual(port["state"], "FILTERED")
                self.assertEqual(port["reason"], "ACK_TIMEOUT")

    def test_connect_transport_is_rejected_before_raw_access_in_either_order(self):
        for options in (
            ["-sA", "--transport", "connect"],
            ["--transport", "connect", "-sA"],
        ):
            with self.subTest(options=options):
                result = self.invoke(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("TCP ACK requires", result.stderr)

    def test_native_ack_and_alias_select_same_raw_transport(self):
        # Nonexistent interface ensures this policy test cannot transmit packets.
        alias = self.invoke(["-sA", "--interface", "skan-no-if"])
        native = self.invoke(["--method", "ack", "--interface", "skan-no-if"])
        self.assertNotEqual(alias.returncode, 0)
        self.assertEqual(native.returncode, alias.returncode)
        self.assertEqual(native.stdout, alias.stdout)
        self.assertEqual(native.stderr, alias.stderr)

    def test_conflicting_tcp_methods_are_rejected(self):
        for method in (["-sT"], ["-sS"], ["--method", "connect"], ["--method", "syn"]):
            for options in (["-sA", *method], [*method, "-sA"]):
                with self.subTest(options=options):
                    result = self.invoke(["--transport", "offline", *options])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("conflicting TCP scan methods", result.stderr)

    def test_legacy_aliases_preserve_explicit_offline_transport(self):
        for alias in ("-sT", "-sS", "-sU", "-sn"):
            for options in ([alias, "--transport", "offline"], ["--transport", "offline", alias]):
                with self.subTest(options=options):
                    result = self.invoke(options)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIsInstance(json.loads(result.stdout)["hosts"], list)

    def test_ack_rejects_service_and_os_detection_at_cli_boundary(self):
        for detection in ("-sV", "-O", "--service-detect", "--os-detect"):
            with self.subTest(detection=detection):
                result = self.invoke(["--transport", "offline", "-sA", detection])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("TCP ACK cannot be combined", result.stderr)


if __name__ == "__main__":
    unittest.main()
