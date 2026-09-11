from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.corpus.compiler import CompilerError, compile_corpus, validate_runtime_graph, write_compiled_corpus
from tools.corpus.model import ActiveProbeSemantics, OSFingerprintSemantics, OSSignature, ServiceMatcherSemantics, UDPProbeSemantics, stable_record_id
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


def with_canonical_id(record):
    return replace(record, id=stable_record_id(record))


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
        active = next(record for record in value if record.kind == "active_probe")
        assert isinstance(active.body, ActiveProbeSemantics)
        duplicate_name = with_canonical_id(replace(active, body=replace(active.body, declaration_order=1, payload_hex="42")))
        with self.assertRaisesRegex(CompilerError, "duplicate probe name"):
            validate_runtime_graph(value + (duplicate_name,))
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
            (matcher, with_canonical_id(replace(matcher, body=replace(matcher.body, probe_name="Absent"))), "unresolved matcher probe"),
            (active, with_canonical_id(replace(active, body=replace(active.body, fallback_probe_names=("Absent",)))), "unresolved fallback"),
        )
        for original, changed, message in replacements:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CompilerError, message):
                    validate_runtime_graph(tuple(changed if record is original else record for record in value))
        for changed, message in (
            (with_canonical_id(replace(dns, body=replace(dns.body, name="Other", declaration_order=2))), "duplicate UDP port"),
            (with_canonical_id(replace(dns, body=replace(dns.body, name="DNS", destination_port=54, declaration_order=2))), "duplicate UDP name"),
            (with_canonical_id(replace(ipv4, body=replace(ipv4.body, name="Other", runtime_id=ipv4.body.runtime_id))), "duplicate OS runtime ID"),
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
        changed_active = with_canonical_id(replace(active, body=replace(active.body, declaration_order=2)))
        with self.assertRaisesRegex(CompilerError, "declaration_order"):
            validate_runtime_graph(tuple(changed_active if record is active else record for record in value))
        changed_rule = with_canonical_id(replace(matcher, body=replace(matcher.body, rule_order=2)))
        with self.assertRaisesRegex(CompilerError, "rule_order"):
            validate_runtime_graph(tuple(changed_rule if record is matcher else record for record in value))
        changed_matcher = with_canonical_id(replace(matcher, body=replace(matcher.body, product="a#b\\c\"d")))
        compiled = compile_corpus(tuple(changed_matcher if record is matcher else record for record in value))
        self.assertIn(b'product="a#b\\\\c\\"d"', compiled.service_probes)

    def test_rejects_noncontiguous_udp_orders(self) -> None:
        value = records()
        dns = next(record for record in value if record.kind == "udp_probe" and record.body.destination_port == 53)
        assert isinstance(dns.body, UDPProbeSemantics)
        changed = with_canonical_id(replace(dns, body=replace(dns.body, declaration_order=2)))
        with self.assertRaisesRegex(CompilerError, "UDP declaration_order"):
            validate_runtime_graph(tuple(changed if record is dns else record for record in value))

    def test_canonicalizes_os_signatures_and_maps_udp_range(self) -> None:
        value = records()
        ipv4 = next(record for record in value if record.kind == "os_fingerprint" and record.body.address_family == "ipv4")
        assert isinstance(ipv4.body, OSFingerprintSemantics)
        sorted_body = replace(
            ipv4.body,
            signatures=(
                OSSignature("ttl", "eq", 64),
                OSSignature("udp_payload_length", "range", (1, 2)),
                OSSignature("window", "eq", 1024),
            ),
        )
        sorted_record = with_canonical_id(replace(ipv4, body=sorted_body))
        unordered_record = replace(
            sorted_record,
            body=replace(sorted_body, signatures=tuple(reversed(sorted_body.signatures))),
        )
        ordered = compile_corpus(tuple(sorted_record if record is ipv4 else record for record in value))
        unordered = compile_corpus(tuple(unordered_record if record is ipv4 else record for record in value))
        self.assertEqual(ordered.ipv4_os, unordered.ipv4_os)
        self.assertIn(b"UDP_PAYLOAD_RANGE=1-2\n", unordered.ipv4_os)

    def test_compiles_and_reimports_each_supported_os_signature_mapping(self) -> None:
        value = records()
        ipv4 = next(record for record in value if record.kind == "os_fingerprint" and record.body.address_family == "ipv4")
        assert isinstance(ipv4.body, OSFingerprintSemantics)
        cases = (
            (OSSignature("ttl", "eq", 1), b"TTL=1\n"),
            (OSSignature("ttl", "range", (1, 2)), b"TTL_RANGE=1-2\n"),
            (OSSignature("dont_fragment", "bool", True), b"DF=Y\n"),
            (OSSignature("window", "eq", 1), b"WINDOW=1\n"),
            (OSSignature("window", "range", (1, 2)), b"WINDOW_RANGE=1-2\n"),
            (OSSignature("mss", "eq", 1), b"MSS=1\n"),
            (OSSignature("window_scale", "eq", 1), b"WSCALE=1\n"),
            (OSSignature("sack_permitted", "bool", True), b"SACK=Y\n"),
            (OSSignature("timestamps", "bool", True), b"TIMESTAMP=Y\n"),
            (OSSignature("tcp_options", "tcp_options", ("MSS", "SACK")), b"TCP_OPTIONS=MSS,SACK\n"),
            (OSSignature("tcp_flags", "eq", 1), b"TCP_FLAGS=1\n"),
            (OSSignature("ack_behavior", "text", "ACKNOWLEDGES_SYN"), b"ACK_BEHAVIOR=ACKNOWLEDGES_SYN\n"),
            (OSSignature("sequence_behavior", "text", "INCREMENTAL"), b"SEQUENCE_BEHAVIOR=INCREMENTAL\n"),
            (OSSignature("response_behavior", "text", "SYN_ACK"), b"RESPONSE_BEHAVIOR=SYN_ACK\n"),
            (OSSignature("icmp_ttl", "eq", 1), b"ICMP_TTL=1\n"),
            (OSSignature("icmp_ttl", "range", (1, 2)), b"ICMP_TTL_RANGE=1-2\n"),
            (OSSignature("icmp_type", "eq", 1), b"ICMP_TYPE=1\n"),
            (OSSignature("icmp_code", "eq", 1), b"ICMP_CODE=1\n"),
            (OSSignature("udp_payload_length", "eq", 1), b"UDP_PAYLOAD_LENGTH=1\n"),
            (OSSignature("udp_payload_length", "range", (1, 2)), b"UDP_PAYLOAD_RANGE=1-2\n"),
            (OSSignature("udp_response_behavior", "text", "UDP_RESPONSE"), b"UDP_RESPONSE_BEHAVIOR=UDP_RESPONSE\n"),
            (OSSignature("response_presence", "bool", True), b"RESPONSE_PRESENCE=Y\n"),
        )
        for signature, directive in cases:
            with self.subTest(signature=signature):
                changed = with_canonical_id(replace(ipv4, body=replace(ipv4.body, signatures=(signature,))))
                compiled = compile_corpus(tuple(changed if record is ipv4 else record for record in value))
                self.assertIn(directive, compiled.ipv4_os)
                regenerated = parse_os_runtime(compiled.ipv4_os, "ipv4", ImportContext(POLICY, "data/os-fingerprints.db"))
                self.assertEqual([record.id for record in regenerated], [changed.id])

    def test_rejects_collection_and_final_artifact_limits_before_staging(self) -> None:
        value = records()
        active = next(record for record in value if record.kind == "active_probe")
        assert isinstance(active.body, ActiveProbeSemantics)
        extra_probes = tuple(
            with_canonical_id(replace(active, body=replace(active.body, probe_name=f"Extra{index}", declaration_order=index)))
            for index in range(1, 257)
        )
        with self.assertRaisesRegex(CompilerError, "service probe count"):
            compile_corpus(value + extra_probes)

        compiled = compile_corpus(value)
        for oversized_service in (b"x" * ((1 << 20) + 1), b"x" * ((16 << 10) + 1)):
            with self.subTest(size=len(oversized_service)):
                manifest = json.loads(compiled.manifest)
                manifest["artifacts"]["service-probes.db"] = "sha256:" + hashlib.sha256(oversized_service).hexdigest()
                oversized = replace(compiled, service_probes=oversized_service, manifest=json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(CompilerError):
                        write_compiled_corpus(Path(directory), oversized)

    def test_rejects_tampered_compiled_manifest_before_staging(self) -> None:
        compiled = compile_corpus(records())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            sentinel = output / "manifest.json"
            sentinel.write_bytes(b"sentinel")
            with self.assertRaisesRegex(CompilerError, "manifest"):
                write_compiled_corpus(output, replace(compiled, manifest=b'{"artifacts":{}}\n'))
            self.assertEqual(sentinel.read_bytes(), b"sentinel")

    def test_rejects_manifest_counts_and_ids_not_bound_to_artifacts(self) -> None:
        compiled = compile_corpus(records())
        manifest = json.loads(compiled.manifest)
        manifest["record_counts"]["active_probe"] = 99
        manifest["record_ids"] = list(reversed(manifest["record_ids"]))
        tampered = replace(compiled, manifest=json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(CompilerError, "manifest"):
                write_compiled_corpus(Path(directory), tampered)


if __name__ == "__main__":
    unittest.main()
