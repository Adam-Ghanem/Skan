# CORE-03 Context Key Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline, then one fresh whole-diff reviewer. Steps use checkbox syntax for tracking.

**Goal:** Bind the TCP correlation registry to local endpoint and capture context.
**Architecture:** Extend the existing exact-equality key, use one validated factory, retain the IPv4 fast lookup, and require registry presence after candidate validation on other paths.
**Tech Stack:** C++20, GNU Make, Python, isolated Linux namespace lab.
**Spec:** `docs/superpowers/specs/2026-10-05-core03-context-key.md`.

## Global Constraints

- No tuple/parser weakening, Nmap delegation, public scans, dependencies or CI waits.
- Session ownership does not imply on-wire replay prevention; document remaining gaps.
- Reuse the isolated `core/v3-correlation` worktree; never touch historical dirty work.

## Review Focus

- IPv6 scope equality and hash must stay consistent.
- Wrong capture ownership must never fall back to a less specific key.
- ICMP errors must retain strict quote validation before registry lookup.
- Bare RST ambiguity must not choose an arbitrary pending submission.
- Legacy generic keys must not become wildcards matching contextual live keys.

### Task 1: contextual identity and transport integration

**Files:** Modify `include/net/packet_filter.hpp`, `src/net/packet_filter.cpp`,
`include/net/network_scan_transport.hpp`, `src/net/network_scan_transport.cpp`;
test `tests/unit/net/test_packet_filter.cpp`, `tests/unit/net/test_network_scan_transport.cpp`.

**Interfaces:** Consumes `PortSubmission`, `IpAddress`, `ScanSession` and current exact registry.
Produces `optional<CorrelationKey> tcp_correlation_key(const PortSubmission&, uint32_t, uint64_t)`
and key fields `source_ip`, `protocol`, `interface_index`, `scan_generation`.

- [x] Add real factory/registry tests. For both families insert token 73, mutate each context field independently and assert NotFound, then original Found/token 73. Include scope mismatches and invalid factory arguments.
- [x] Run `timeout -k 3s 90s make -j2 build/test_packet_filter build/test_network_scan_transport`; expect missing API RED, then a behavioral RED after extracting the legacy projection into the factory.
- [x] Extend equality/hash to all context fields; reject invalid factory arguments. Integrate both TCP families and strict ICMP/ACK candidate paths, retaining IPv4 fast lookup and all original validators.
- [x] Review-driven coverage: extract `detail::resolve_tcp_response` using the adapter's real pending-map state. Test both-family ACK and ICMP receive decisions, missing/wrong registry authority, wrong context and ambiguity without callback effects. Verify deletion of the registry guard fails these tests, then restore and rerun.
- [x] Run bounded factory, parser, scheduler and UDP unit tests; expect exit 0. Run the CORE-01 smoke lab and sanitizer targets; expect exit 0 and independent SYN/ACK/UDP truth assertions unchanged.
- [x] Independent review; fix important findings with RED/GREEN tests. Review full diff and record exact outcomes/limits in `docs/CORE03_CONTEXT_CORRELATION.md`.
- [x] Commit and push verified work; verify remote branch SHA without CI polling or merge. Published `39dd8c2d804b6bd4dfab149fca357c361595eac5`; the remote branch SHA matched. No merge or CI status claim.
