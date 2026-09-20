# Phase 34 Advanced Scan Types Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a capability-honest, first-party TCP ACK firewall-mapping scan with Nmap-style `-sA`.

**Architecture:** `TcpAckProbe` owns ACK packet construction and classification. The existing scheduler, Linux raw transport, IO reactor, correlation table, and canonical writers remain the only data path; Linux raw is default, offline is explicit simulation, and Connect is rejected.

**Tech Stack:** C++20, existing AF_PACKET transport, IOEngine, Make, GitHub Actions isolated namespace.

**Spec:** `docs/superpowers/specs/2026-09-02-phase-34-advanced-scan-types-design.md`

## Global Constraints

- RST means `UNFILTERED`; deadline timeout means `FILTERED`; ACK scanning never claims `OPEN` or `CLOSED`.
- No silent fallback, shell execution, threads, public target, Nmap code/data, stealth/evasion, spoofing, fragmentation, idle, Window, SCTP, or IP-protocol feature.
- Continue bounded target/rate behavior, capability-honest raw errors, safe text output, and the existing single reactor.

---

### Task 1: Typed ACK probe

**Files:** modify `include/portscan/port_types.hpp`, `src/portscan/port_types.cpp`, `include/portscan/port_probe.hpp`, `Makefile`; create `include/portscan/tcp_ack.hpp`, `src/portscan/tcp_ack.cpp`; test `tests/unit/portscan/test_port_probe.cpp`.

**Interfaces:** Produces `ScanProbeType::TcpAck`, `ScanReason::AckRst`, `ScanReason::AckTimeout`, and `TcpAckProbe` for the existing scheduler.

- [ ] Write failing assertions for stable names (`ack`, `ACK_RST`, `ACK_TIMEOUT`), ACK-only bytes, correct RST -> `UNFILTERED`, timeout -> `FILTERED`, plus wrong tuple/sequence, SYN/ACK, malformed, duplicate, and late responses rejected.
- [ ] Run `make -j2 build/test_port_probe && ./build/test_port_probe`; expect missing enum/probe failure.
- [ ] Implement `TcpAckProbe` with deterministic nonzero sequence/acknowledgement identity. Its assessment must require matching family, address tuple, ports, submission identity, RST flag, and expected reset sequence.
- [ ] Re-run `make -j2 build/test_port_probe && ./build/test_port_probe`; expect every assertion green.
- [ ] Commit with `feat: add typed TCP ACK probe`.

### Task 2: Scheduler and config contract

**Files:** modify `src/portscan/port_scheduler.cpp`, `src/portscan/port_probe.cpp`, `src/orchestrator/scan_config.cpp`; test `tests/unit/portscan/test_port_scheduler.cpp`, `tests/unit/orchestrator/test_scan_config.cpp`.

**Interfaces:** Consumes `TcpAckProbe`; produces deterministic ACK scheduling, explicit `linux|offline` acceptance, and rejection of ACK+Connect, ACK+service detection, and ACK+OS detection.

- [ ] Add failing tests asserting a recording submission has `TcpAck` and every prohibited configuration reports an error.
- [ ] Run `make -j2 build/test_port_scheduler build/test_scan_config && ./build/test_port_scheduler && ./build/test_scan_config`; expect ACK failures.
- [ ] Select `TcpAckProbe` only for ACK method. Keep cancellation, retry, ordering, and limits. Offline must emit only deterministic timeout-style evidence, never fabricated open/closed results.
- [ ] Re-run the focused tests; expect ACK and existing SYN/Connect cases green.
- [ ] Commit with `feat: schedule capability-gated ACK scans`.

### Task 3: Probe-specific raw correlation

**Files:** modify `include/net/network_scan_transport.hpp`, `src/net/network_scan_transport.cpp`; test `tests/unit/net/test_network_scan_transport.cpp`, `tests/unit/net/test_packet_receiver.cpp`.

**Interfaces:** Consumes ACK submission identity and produces Linux raw support for exactly `TcpSyn` and `TcpAck` with strict TCP/ICMP correlation.

- [ ] Add failing tests that ACK is supported; an exact RST completes `UNFILTERED`; wrong ACK number, endpoint, quote, malformed, duplicate, and late observations do not complete a submission.
- [ ] Run `make -j2 build/test_network_scan_transport build/test_packet_receiver && ./build/test_network_scan_transport && ./build/test_packet_receiver`; expect ACK support/correlation failures.
- [ ] Permit only SYN and ACK in `supports()`/`submit()`. Preserve generic frame composition and packet parsing; match family, source/destination, ports, persisted identity, RST semantics, and exact ICMP-quoted original packet before handing evidence to the probe.
- [ ] Re-run focused raw tests; expect ACK checks and existing SYN regression checks green.
- [ ] Commit with `feat: correlate raw TCP ACK responses`.

### Task 4: CLI and canonical output

**Files:** modify `src/main.cpp`; test `tests/integration/cli/test_nmap_compat.sh`, `tests/integration/cli/test_terminal_policy.py`, and normal/JSON/XML/grepable writer tests.

**Interfaces:** Produces `-sA`/`--method ack`, stable `probe=ack`/reasons, and explicit error paths.

- [ ] Add a failing offline CLI regression that parses JSON and expects `probe == "ack"`, `state == "FILTERED"`, `reason == "ACK_TIMEOUT"`; add visible failures for `-sA --transport connect`, `-sA -sV`, and `-sA -O`; prove `--open` excludes `UNFILTERED`.
- [ ] Run `make -j2 all && bash tests/integration/cli/test_nmap_compat.sh && python3 tests/integration/cli/test_terminal_policy.py`; expect `-sA` unrecognized.
- [ ] Add aliases/help/config wiring. Preserve Linux default, explicit offline-only-on-request, current safe terminal behavior, and no service/OS stage for ACK results.
- [ ] Re-run the CLI/writer commands; expect deterministic offline results and green legacy policies.
- [ ] Commit with `feat: add Nmap-style TCP ACK scan CLI`.

### Task 5: Private-lab acceptance and docs

**Files:** modify `.github/workflows/ci.yml`, `README.md`, `docs/NMAP_COMPATIBILITY.md`, `ARCHITECTURE.md`, `NEXT_PHASE_ROADMAP.md`.

**Interfaces:** Consumes working raw `-sA`; produces dual-stack private namespace evidence and accurate capability documentation.

- [ ] Add failing isolated-lab assertions against only `192.0.2.2`/`2001:db8:29::2` for `UNFILTERED/ACK_RST`, retaining existing capture artifacts.
- [ ] Run `./bin/skan -sA --transport linux -p 8080 --interface lo 127.0.0.1`; expect structured AF_PACKET failure in restricted environments, never fallback.
- [ ] Add namespace acceptance, explain firewall-mapping semantics and offline simulation, and document every deferred advanced family as unsupported.
- [ ] Run `make -j2 test && make check-line-endings && make check-version && bash tests/integration/cli/test_nmap_compat.sh && python3 tests/integration/cli/test_terminal_policy.py`; expect green suite with only existing capability-gated skips.
- [ ] Commit with `docs: define TCP ACK scan capability`.

### Task 6: Delivery gate

**Files:** review complete diff against `main`; test local suite and GitHub CI.

- [ ] Run `git diff --check`, the full suite, CLI regressions, and an independent review focused on correlation, privilege policy, output parity, and CLI ambiguity.
- [ ] Fix each concrete review finding with a focused regression; push `codex/nmap-phase-34-advanced-scan-types` and create a PR.
- [ ] Require green core/debug/release/ASan/UBSan/coverage/fuzz/static/isolated-lab/Debian checks before merge, then fast-forward local `main` after remote merge.

## Plan Self-Review

- Tasks 1–3 cover typed construction, scheduling, and strict correlation; Task 4 covers CLI/output; Task 5 covers live acceptance/docs; Task 6 gates delivery.
- The plan uses one stable type/name set before each consumer and contains no unresolved implementation placeholders.
