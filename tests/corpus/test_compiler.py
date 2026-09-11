from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.compiler import CompilerError, compile_corpus, validate_runtime_graph, write_compiled_corpus
from tools.corpus.model import ActiveProbeSemantics, ServiceMatcherSemantics, UDPProbeSemantics, stable_record_id
from tools.corpus.runtime import ImportContext, parse_os_runtime, parse_service_runtime, parse_udp_runtime
from tools.corpus.sources import load_source_manifest


ROOT = Path(__file__).resolve().parents[2]
POLICY = load_source_manifest(ROOT / "corpus" / "sources" / "sources.json")["skan-first-party"]


def records():
    service = parse_service_runtime(
        b'Probe TCP Ping rarity=2 priority=40 timeout=1000 ports=7 protocol=tcp\n'
        b'send "A\\r\\n"\n'
        b'match type=prefix pattern="A" service=echo confidence=0.5\n',
        ImportContext(POLICY, "data/service-probes.db"),
    )
    udp = parse_udp_runtime(
        b"probe DNS 53 dns 512 1234\nprobe DEFAULT 0 generic 512 00\n",
        ImportContext(POLICY, "data/udp-probes.db"),
    )
    ipv4 = parse_os_runtime(
        b"Fingerprint Alpha\nID=alpha\nSPECIFICITY=1\nADDRESS_FAMILY=IPv4\n"
        b"Class Example | Family\nTTL=64\n",
        "ipv4",
        ImportContext(POLICY, "data/os-fingerprints.db"),
    )
    ipv6 = parse_os_runtime(
        b"Fingerprint Beta\nID=beta\nSPECIFICITY=1\nADDRESS_FAMILY=IPv6\n"
        b"Class Example | Family\nTTL=64\n",
        "ipv6",
        ImportContext(POLICY, "data/os-fingerprints-v6.db"),
    )
    return service + udp + ipv4 + ipv6


class CorpusCompilerTests(unittest.TestCase):
    def test_compiles_exact_lf_runtime_artifacts_and_manifest_hashes(self) -> None:
        compiled = compile_corpus(records())
        self.assertEqual(
            compiled.service_probes,
            b'Probe TCP Ping rarity=2 priority=40 timeout=1000 ports=7 protocol=tcp\n'
            b'send "A\\r\\n"\n'
            b'match type=prefix pattern="A" service="echo" confidence=0.5\n',
        )
        self.assertEqual(
            compiled.udp_probes,
            b"# Generated from Skan Intelligence Database v2 canonical UDP records.\n"
            b"# Syntax: probe NAME PORT PROTOCOL_HINT MAX_RESPONSE_BYTES PAYLOAD_HEX\n"
            b"probe DNS 53 dns 512 1234\nprobe DEFAULT 0 generic 512 00\n",
        )
        self.assertEqual(
            compiled.ipv4_os,
            b"Fingerprint Alpha\nID=alpha\nSPECIFICITY=1\nADDRESS_FAMILY=IPv4\nClass Example | Family\nTTL=64\n",
        )
        self.assertEqual(
            compiled.ipv6_os,
            b"Fingerprint Beta\nID=beta\nSPECIFICITY=1\nADDRESS_FAMILY=IPv6\nClass Example | Family\nTTL=64\n",
        )
        manifest = json.loads(compiled.manifest)
        self.assertEqual(manifest["artifacts"]["service-probes.db"], "sha256:" + hashlib.sha256(compiled.service_probes).hexdigest())
        self.assertTrue(compiled.manifest.endswith(b"\n"))

    def test_is_deterministic_and_writes_only_after_complete_validation(self) -> None:
        first = compile_corpus(records())
        self.assertEqual(first, compile_corpus(tuple(reversed(records()))))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            sentinel = output / "service-probes.db"
            manifest = output / "manifest.json"
            sentinel.write_bytes(b"sentinel")
            manifest.write_bytes(b"manifest-sentinel")
            with self.assertRaises(CompilerError):
                write_compiled_corpus(output, compile_corpus(records()[:-1]))
            self.assertEqual(sentinel.read_bytes(), b"sentinel")
            self.assertEqual(manifest.read_bytes(), b"manifest-sentinel")
            write_compiled_corpus(output, first)
            self.assertEqual((output / "manifest.json").read_bytes(), first.manifest)

    def test_reimports_to_the_same_semantic_record_ids(self) -> None:
        compiled = compile_corpus(records())
        regenerated = (
            parse_service_runtime(compiled.service_probes, ImportContext(POLICY, "data/service-probes.db"))
            + parse_udp_runtime(compiled.udp_probes, ImportContext(POLICY, "data/udp-probes.db"))
            + parse_os_runtime(compiled.ipv4_os, "ipv4", ImportContext(POLICY, "data/os-fingerprints.db"))
            + parse_os_runtime(compiled.ipv6_os, "ipv6", ImportContext(POLICY, "data/os-fingerprints-v6.db"))
        )
        self.assertEqual({record.id for record in regenerated}, {record.id for record in records()})

    def test_rejects_incomplete_unverified_and_invalid_graphs(self) -> None:
        value = records()
        with self.assertRaisesRegex(CompilerError, "all four"):
            validate_runtime_graph(value[:-1])
        with self.assertRaisesRegex(CompilerError, "verified"):
            validate_runtime_graph((replace(value[0], status="imported"),) + value[1:])
        with self.assertRaisesRegex(CompilerError, "duplicate probe name"):
            validate_runtime_graph(value + (value[0],))
        with self.assertRaisesRegex(CompilerError, "DEFAULT"):
            validate_runtime_graph(tuple(record for record in value if record.kind != "udp_probe" or record.body.destination_port != 0))

    def test_rejects_every_cross_record_reference_and_identity_conflict(self) -> None:
        value = records()
        active = next(record for record in value if record.kind == "active_probe")
        matcher = next(record for record in value if record.kind == "service_matcher")
        dns = next(record for record in value if record.kind == "udp_probe" and record.body.destination_port == 53)
        ipv4 = next(record for record in value if record.kind == "os_fingerprint" and record.body.address_family == "ipv4")
        assert isinstance(active.body, ActiveProbeSemantics)
        assert isinstance(matcher.body, ServiceMatcherSemantics)
        assert isinstance(dns.body, UDPProbeSemantics)
        replacements = (
            (matcher, replace(matcher, body=replace(matcher.body, probe_name="Absent")), "unresolved matcher probe"),
            (active, replace(active, body=replace(active.body, fallback_probe_names=("Absent",))), "unresolved fallback"),
        )
        for original, changed, message in replacements:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CompilerError, message):
                    validate_runtime_graph(tuple(changed if record is original else record for record in value))
        for changed, message in (
            (replace(dns, body=replace(dns.body, name="Other")), "duplicate UDP port"),
            (replace(dns, body=replace(dns.body, name="DNS")), "duplicate UDP name"),
            (replace(ipv4, body=replace(ipv4.body, name="Other", runtime_id=ipv4.body.runtime_id)), "duplicate OS runtime ID"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(CompilerError, message):
                    validate_runtime_graph(value + (changed,))

    def test_rejects_noncontiguous_orders_and_escapes_runtime_text_tokens(self) -> None:
        value = records()
        active = next(record for record in value if record.kind == "active_probe")
        matcher = next(record for record in value if record.kind == "service_matcher")
        assert isinstance(active.body, ActiveProbeSemantics)
        assert isinstance(matcher.body, ServiceMatcherSemantics)
        with self.assertRaisesRegex(CompilerError, "declaration_order"):
            validate_runtime_graph(tuple(replace(active, body=replace(active.body, declaration_order=2)) if record is active else record for record in value))
        with self.assertRaisesRegex(CompilerError, "rule_order"):
            validate_runtime_graph(tuple(replace(matcher, body=replace(matcher.body, rule_order=2)) if record is matcher else record for record in value))
        changed_matcher = replace(matcher, body=replace(matcher.body, product="a#b\\c\"d"))
        changed_matcher = replace(changed_matcher, id=stable_record_id(changed_matcher))
        compiled = compile_corpus(tuple(changed_matcher if record is matcher else record for record in value))
        self.assertIn(b'product="a#b\\\\c\\"d"', compiled.service_probes)

    def test_rejects_tampered_compiled_manifest_before_staging(self) -> None:
        compiled = compile_corpus(records())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            sentinel = output / "manifest.json"
            sentinel.write_bytes(b"sentinel")
            with self.assertRaisesRegex(CompilerError, "manifest"):
                write_compiled_corpus(output, replace(compiled, manifest=b'{"artifacts":{}}\n'))
            self.assertEqual(sentinel.read_bytes(), b"sentinel")


if __name__ == "__main__":
    unittest.main()
