# CORE-03 live SYN correlation repair

> **For agentic workers:** Use superpowers:executing-plans for this bounded diagnostic repair, with an independent whole-diff review before integration.

**Goal:** Investigate independently captured OPEN/CLOSED SYN responses reported as timeouts, and fix proven rejection defects without loosening correlation. Do not infer the historical cause from a successful clean rebuild.

**Architecture:** Retain the first-party parser, tuple validator, correlation table and scheduler. Trace their boundaries and change only the proven faulty boundary. The base does not yet have explicit scan/probe generation fields; this repair does not claim to complete correlation V3 or delete identity checks.

**Tech Stack:** C++20, GNU Make, Python, authorized Linux namespace lab.

**Spec:** User's end-to-end trace request; `docs/CORE_SCANNER_V3_AUDIT.md` correlation gaps and `docs/PORT_STATE_SEMANTICS.md` state contract.

## Global constraints

- Base: `b75afca` (latest fetched origin/main); branch `core/v3-correlation`.
- Preserve the dirty historical CORE-02 worktree; do not transfer its unverified changes.
- No public scan targets, Nmap delegation, weaker tuple checks or bypasses.
- Bounded local commands; no GitHub CI polling or waiting; no claim of phase acceptance without exact-head evidence.

## Review focus

- Correct wire acknowledgments and tuple can still fail at a later boundary.
- Closed-port RST and open-port SYN/ACK must have the same source/destination identity rules.
- Malformed checksums, wrong destination and wrong sequence/ack must stay rejected.
- Source-interface scope must not be synthesized from untrusted packet addresses.
- Missing generation fields are an explicit remaining CORE-03 gap, not a hidden claim of protection.

### Task 1: locate the rejecting boundary

Files: `src/net/network_scan_transport.cpp`, `src/net/packet_receiver.cpp`, `src/portscan/port_scheduler.cpp`; local ignored capture diagnostics.

- [x] Attempt reproduction from the latest base and inspect independent packet evidence (clean base passes; historical executable still fails).
- [x] Record submission/key, wire SYN/reply, parser status, validation field, lookup and lifecycle/evidence decision; debug-only logs must not alter classification.
- [x] Identify the first failing boundary with actual output, not a timing assumption (debugger: scheduler lifecycle, received-after-deadline).

The historical MSS-only SYN/ACK and optionless RST/ACK pass current replay and
live validation. Read-only debugger inspection of the preserved failing binary
identified its scheduler's received-after-deadline rejection after successful
tuple/ACK lookup and probe assessment. Instrumentation delay is not claimed as
network latency. Independent review also found a separate lossy TCP
re-serialization rejection, reproduced by RED tests; that related defect is
repaired below, not substituted as the historical rejection's explanation.

### Task 2: minimal repair, RED then GREEN

Files: the proven faulty boundary and its existing unit test; no unrelated changes.

- [x] Add deterministic literal captured and synthetic option/padding regressions.
- [x] Observe the unknown-option extraction regression fail; preserve validated wire bytes instead of reconstructing the lossy model.
- [x] Keep malformed, wrong tuple/ACK, retired lookup and opposite-family negative tests passing. Explicit generation-based rejection remains unimplemented, not claimed.

### Task 3: validate and publish

Files: lab acceptance tests and `docs/CORE03_SYN_REPAIR.md` execution ledger.

- [x] Build and run SYN OPEN/CLOSED IPv4/IPv6, ACK IPv4/IPv6 and UDP IPv4 live truth with independent listener/firewall/capture evidence; record the existing non-loopback UDP IPv6 gap.
- [x] Run locally available relevant/full tests, sanitizers where practical; record failures/timeouts/skips.
- [x] Inspect full diff, perform independent review, commit and push valid fixes to the phase branch.
- [x] Leave full CORE-03 generation/key expansion and CI acceptance explicitly incomplete if not implemented/verified; never merge red or pending CI.

The broader phase is not complete: generation-aware identity/expiry expansion,
kernel arrival timestamps and live non-loopback IPv6 UDP coverage remain gaps.
Published fixes are scoped to proven wire preservation, diagnostic visibility
and hash-bound fixture checkout stability; no stronger correlation claim is made.
