from __future__ import annotations

import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.iana_services import parse_iana_csv


CTX = AdapterContext(
    source_id="iana-services",
    revision="2026-09-04",
    source_url="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
    source_license="CC0-1.0",
    source_hash="sha256:" + "b" * 64,
)


class IanaAdapterTests(unittest.TestCase):
    def test_expands_ranges_and_keeps_registry_as_metadata(self) -> None:
        csv_text = """Service Name,Port Number,Transport Protocol,Description,Assignment Notes\nexample,100-101,tcp,Example Service,Example note\ndomain,53,udp,Domain Name Server,\n"""
        records = parse_iana_csv(csv_text, CTX)
        self.assertEqual([r.ports for r in records], [(53,), (100,), (101,)])
        self.assertTrue(all(r.kind == "port_registry" for r in records))
        self.assertTrue(all(r.confidence is None for r in records))
        self.assertTrue(all(r.confidence_basis == "metadata" for r in records))

    def test_preserves_reserved_rows_instead_of_dropping_registry_coverage(self) -> None:
        csv_text = """Service Name,Port Number,Transport Protocol,Description\n,102,tcp,Reserved\n"""
        record = parse_iana_csv(csv_text, CTX)[0]
        self.assertEqual(record.service, "reserved")
        self.assertEqual(record.ports, (102,))

    def test_rejects_invalid_port_range(self) -> None:
        csv_text = """Service Name,Port Number,Transport Protocol,Description\nx,99999,tcp,bad\n"""
        with self.assertRaisesRegex(ValueError, "port"):
            parse_iana_csv(csv_text, CTX)


if __name__ == "__main__":
    unittest.main()
