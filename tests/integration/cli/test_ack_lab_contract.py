#!/usr/bin/env python3
"""Offline checks of the isolated ACK acceptance harness itself."""

import os
import unittest
from unittest.mock import patch

import test_ack_private_lab as lab


class LabContractTests(unittest.TestCase):
    def test_explicit_rows(self):
        xml = '<nmaprun><host><ports><port portid="80"><state state="unfiltered"/></port></ports></host></nmaprun>'
        self.assertEqual(lab.nmap_states(xml, [80]), {80: "UNFILTERED"})

    def test_summary_rows(self):
        xml = ('<nmaprun><host><ports><extraports state="unfiltered" count="2"/>'
               '<port portid="53"><state state="filtered"/></port></ports></host></nmaprun>')
        self.assertEqual(lab.nmap_states(xml, [53, 80, 443]),
                         {53: "FILTERED", 80: "UNFILTERED", 443: "UNFILTERED"})

    def test_missing_or_ambiguous_evidence_is_not_inferred(self):
        for body in ('', '<extraports state="unfiltered" count="1"/>',
                     '<extraports state="unfiltered" count="1"/><extraports state="filtered" count="1"/>'):
            with self.subTest(body=body), self.assertRaises(AssertionError):
                lab.nmap_states(f'<nmaprun><host><ports>{body}</ports></host></nmaprun>', [80, 443])

    def test_unauthorized_execution_exits_before_any_command(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(lab.subprocess, "run") as run:
            with self.assertRaisesRegex(SystemExit, "Refusing raw tests"):
                lab.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
