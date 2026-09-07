import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tools.corpus.io import load_jsonl, write_jsonl
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id
from tools.corpus.sources import load_source_manifest


SOURCES = load_source_manifest(Path("corpus/sources/sources.json"))


def provenance(record_id: str) -> Provenance:
    return Provenance(
        source_id="skan-first-party",
        source_record_id=record_id,
        source_revision="repository",
        source_url="https://github.com/Adam-Ghanem/Skan",
        source_license="MIT",
        source_hash="sha256:" + "b" * 64,
    )


def make_base(kind: str, record_id: str) -> CanonicalRecord:
    return CanonicalRecord(
        id="",
        kind=kind,
        transport="none",
        address_family="none",
        probe_id=None,
        probe_payload_ref=None,
        matcher_type=None,
        matcher_expression=None,
        service=None,
        vendor="Skan",
        product=None,
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(),
        rarity=None,
        confidence=0.9,
        confidence_basis="fixture",
        evidence_requirements=(),
        negative_constraints=(),
        provenance=(provenance(record_id),),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="fixture",
    )


def finalize(record: CanonicalRecord) -> CanonicalRecord:
    return replace(record, id=stable_record_id(record))


def active_probe() -> CanonicalRecord:
    return finalize(replace(
        make_base("active_probe", "probe-http"),
        transport="tcp",
        address_family="any",
        probe_id="HTTPGet",
        probe_payload_hex="474554202f20485454502f312e300d0a0d0a",
        probe_priority=95,
        probe_timeout_ms=1500,
        fallback_probe_ids=("GenericBanner", "LastResort"),
        ports=(80, 8080),
        rarity=1,
    ))


def service_matcher() -> CanonicalRecord:
    return finalize(replace(
        make_base("service_matcher", "match-http"),
        transport="tcp",
        address_family="any",
        probe_id="HTTPGet",
        matcher_type="regex",
        matcher_expression="^HTTP/([0-9.]+)",
        service="http",
        product="HTTP",
        version="$1",
        ports=(80, 8080),
        rarity=1,
        match_strength="soft",
        extra_template="protocol $1",
        hostname_template="$2",
        tunnel_template="tls",
    ))


def udp_probe() -> CanonicalRecord:
    return finalize(replace(
        make_base("udp_probe", "udp-dns"),
        transport="udp",
        address_family="any",
        probe_id="DNS",
        probe_payload_hex="123401000001000000000000",
        protocol_hint="dns",
        max_response_bytes=512,
        ports=(53,),
    ))


def os_fingerprint() -> CanonicalRecord:
    return finalize(replace(
        make_base("os_fingerprint", "os-linux"),
        address_family="ipv4",
        fingerprint_name="SkanLinuxGeneric",
        fingerprint_native_id="skan-linux-generic",
        specificity=13,
        vendor="Skan",
        os_family="Linux",
        os_generation="5.x+",
        device_type="general-purpose",
        os_features=(("DF", "Y"), ("TCP_OPTIONS", "MSS,SACK,TS,NOP,WS"), ("TTL", "64")),
    ))


class RuntimeFidelityJsonlTests(unittest.TestCase):
    def test_each_runtime_kind_round_trips_exactly(self):
        records = [active_probe(), service_matcher(), udp_probe(), os_fingerprint()]
        with tempfile.TemporaryDirectory() as temp:
            for record in records:
                with self.subTest(kind=record.kind):
                    path = Path(temp) / f"{record.kind}.jsonl"
                    write_jsonl(path, [record])
                    self.assertEqual(load_jsonl(path, SOURCES), [record])

    def test_fallback_order_is_preserved_in_json(self):
        record = active_probe()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "probe.jsonl"
            write_jsonl(path, [record])
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["fallback_probe_ids"], ["GenericBanner", "LastResort"])

    def test_os_features_are_serialized_in_deterministic_key_order(self):
        record = finalize(replace(
            os_fingerprint(),
            id="",
            os_features=(("TTL", "64"), ("DF", "Y"), ("WINDOW", "64240")),
        ))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "os.jsonl"
            write_jsonl(path, [record])
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["os_features"],
                [["DF", "Y"], ["TTL", "64"], ["WINDOW", "64240"]],
            )

    def test_payload_hex_is_serialized_lowercase(self):
        record = finalize(replace(active_probe(), id="", probe_payload_hex="AABB00FF"))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "probe.jsonl"
            write_jsonl(path, [record])
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["probe_payload_hex"], "aabb00ff")


if __name__ == "__main__":
    unittest.main()
