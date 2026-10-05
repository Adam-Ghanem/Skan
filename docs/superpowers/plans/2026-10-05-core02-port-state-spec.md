# CORE-02 Port-State Specification Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Independent output/lab/raw workstreams have disjoint ownership.

**Goal:** Make all eight Skan states explicit, testable and consistent with admitted evidence.

**Architecture:** Preserve the existing probes, transports and schedulers. Retain bounded raw observations in current pending records until their already configured attempt deadline so conflicts can be represented. Share canonical enum names across outputs.

**Tech Stack:** C++20, GNU Make, Python lab contracts, Linux WSL, ASan/UBSan.

**Spec:** `docs/CORE_SCANNER_SPEC.md`, `docs/PORT_STATE_SEMANTICS.md`.

## Global constraints

- Only CORE-02; no generation/correlation architecture, timing/retry redesign or new scan families.
- Use `core/v3-port-state-spec`, based on `bf42e4667805553529106e261dda331cd3d7be06`.
- No Nmap code/data; isolated documentation-address/localhost tests only.
- Test behavior changes before implementation. Bounded subprocesses, asynchronous CI.

## Review focus

- Contradictory admitted evidence in both orders must preserve UNKNOWN.
- Capture/socket failures must not manufacture filtering.
- Router ICMP with correct quotes must preserve category and reject wrong quotes.
- Full state names at narrow widths must not be silently shortened.
- Independent truth must reject missing/extra/wrong state/reason results.

### Task 1: raw evidence and taxonomy

Files: TCP SYN/ACK probes, port_probe.hpp, network_scan_transport.cpp,
udp_network_scan_transport.cpp and corresponding unit tests.

- [ ] Add failing table/negative tests for administrative versus path ICMP,
  contradictory flags, invalid quotes, capture failure and router-origin ICMP.
- [ ] Preserve typed ICMP categories and local transport errors. Keep live raw
  callbacks/correlation until explicit cancellation so multiple admitted replies
  can be observed. No changes to correlation key identity.
- [ ] Run bounded probe/transport tests; report exact evidence.

### Task 2: scheduler state semantics

Files: TCP Connect, TCP/UDP schedulers, Pending structs and scheduler tests.

- [ ] Write failing tests for stale response, raw conflicts in both orders,
  duplicate idempotence, malformed UDP and local failures.
- [ ] Retain raw candidate state/reason/time in Pending. At deadline publish
  candidate or current silence policy; differing candidate states latch conflict.
- [ ] Map local Connect failures to ERROR; preserve route errors as UNREACHABLE;
  prevent repeated negatives from overriding an admitted conflict.
- [ ] Run real scheduler/probe table matrix and existing tests.

### Task 3: output consistency

Files: output/result_model.cpp, terminal renderer and output tests.

- [ ] Add failing eight-state/reason/counter and invalid-enum tests.
- [ ] Preserve full OPEN_OR_FILTERED label at all supported widths. Add nonzero
  supplementary counters and wrap safely. Reject invalid enums at report boundary.
- [ ] Verify normal/JSON/XML/grepable/terminal and --open retain same semantics.

### Task 4: independent truth lab

Files: tests/integration/core_lab, docs/CORE_GROUND_TRUTH_LAB.md.

- [ ] Add offline tests requiring exact state/reason/probe sets and timeout safety.
- [ ] Extend smoke using the same isolated lab to SYN drop/admin on both families,
  Connect and UDP truth cases; preserve authorization, captures and cleanup.
- [ ] Run offline contract then live root WSL lab on final scanner build.

### Task 5: verification and integration

- [ ] Run relevant/full suite, production build, ASan/UBSan in separate build
  directories with deadlines. Record all failures and fix reproducible ones.
- [ ] Inspect complete diff, normative docs and independent review.
- [ ] Commit/push focused work; open one PR and attach it to the task.
- [ ] One final CI snapshot after local work is exhausted; never merge red/pending
  or start CORE-03 without accepted final/post-merge evidence.
