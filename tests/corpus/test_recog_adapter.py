from __future__ import annotations

import unittest

from tools.corpus.adapters.common import AdapterContext
from tools.corpus.adapters.recog import parse_recog_xml


CTX = AdapterContext(
    source_id="rapid7-recog",
    revision="v3.1.29",
    source_url="https://github.com/rapid7/recog/blob/v3.1.29/xml/http_xpoweredby.xml",
    source_license="BSD-2-Clause",
    source_hash="sha256:" + "a" * 64,
)


class RecogAdapterTests(unittest.TestCase):
    def test_maps_http_header_fingerprint_and_templates(self) -> None:
        xml = """<fingerprints matches="http_header.x-powered-by" protocol="http" database_type="service" preference="0.90">
          <fingerprint pattern="^PHP/([0-9.]+)$" flags="REG_ICASE">
            <description>PHP</description>
            <param pos="0" name="service.vendor" value="PHP"/>
            <param pos="0" name="service.product" value="PHP"/>
            <param pos="1" name="service.version"/>
            <param pos="0" name="service.cpe23" value="cpe:/a:php:php:{service.version}"/>
          </fingerprint>
        </fingerprints>"""
        records = parse_recog_xml(xml, CTX, source_path="http_xpoweredby.xml")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.kind, "web_fingerprint")
        self.assertEqual(record.evidence_dimension, "http_header")
        self.assertEqual(record.product, "PHP")
        self.assertEqual(record.vendor, "PHP")
        self.assertEqual(record.version, "$1")
        self.assertIn("regex_flag:REG_ICASE", record.evidence_requirements)
        self.assertEqual(record.confidence_basis, "medium:recog-passive")
        self.assertEqual(record.provenance[0].source_id, "rapid7-recog")

    def test_maps_protocol_banner_without_creating_active_probe(self) -> None:
        xml = """<fingerprints matches="ftp.banner" protocol="ftp" database_type="service" preference="0.90">
          <fingerprint pattern="^Microsoft FTP Service$">
            <param pos="0" name="service.vendor" value="Microsoft"/>
            <param pos="0" name="service.product" value="IIS"/>
            <param pos="0" name="service.version" value="5.0"/>
          </fingerprint>
        </fingerprints>"""
        record = parse_recog_xml(xml, CTX, source_path="ftp_banners.xml")[0]
        self.assertEqual(record.kind, "service_matcher")
        self.assertEqual(record.probe_id, "passive:ftp.banner")
        self.assertEqual(record.service, "ftp")
        self.assertEqual(record.product, "IIS")

    def test_supports_multiline_flag_without_changing_pattern(self) -> None:
        xml = """<fingerprints matches="ftp.banner" protocol="ftp" database_type="service">
          <fingerprint pattern="^Apple FTP$" flags="REG_ICASE,REG_MULTILINE">
            <param pos="0" name="service.vendor" value="Apple"/>
            <param pos="0" name="service.product" value="FTP"/>
          </fingerprint>
        </fingerprints>"""
        record = parse_recog_xml(xml, CTX, source_path="ftp_banners.xml")[0]
        self.assertEqual(record.matcher_expression, "^Apple FTP$")
        self.assertIn("regex_flag:REG_MULTILINE", record.evidence_requirements)

    def test_rejects_unknown_regex_flags(self) -> None:
        xml = """<fingerprints matches="ftp.banner" protocol="ftp" database_type="service">
          <fingerprint pattern="x" flags="REG_UNSUPPORTED"/>
        </fingerprints>"""
        with self.assertRaisesRegex(ValueError, "unsupported Recog regex flag"):
            parse_recog_xml(xml, CTX)


if __name__ == "__main__":
    unittest.main()
