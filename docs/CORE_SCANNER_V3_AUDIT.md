# Core Scanner V3 Audit — 2026-10-04

Baseline: `main` at `0bba0da172f208782e6745f8244df3b84992a058`.

This audit is intentionally limited to the core-scanning scope: target planning, discovery, TCP/UDP scanning, packet parsing/construction, correlation, timers/retries, adaptive timing, scheduling/backpressure, port-state evidence, benchmarks, and controlled-lab validation.

## Mainline quality evidence

The latest merge is PR #82. Its source head `e5ad9ce454ad4176e13e895dc3b6d38eba641b24` completed both Skan CI and Fingerprint Corpus CI successfully before merge. The GitHub API currently exposes no separate status record for the merge commit itself, so this audit does not claim a fresh post-merge rerun.

Open PRs #83 and #84 concern service/TLS identity work and are outside this core-scanning phase. They must not be mixed into Core V3 changes.

## Existing core capabilities

- One Linux-first, single-thread-affine `epoll` reactor with one-shot monotonic timers and token-based stale-event protection.
- Deterministic target normalization for IPv4/IPv6, CIDR/ranges/hostnames with bounded expansion.
- TCP Connect, TCP SYN, TCP ACK, and UDP scan paths.
- Explicit Linux raw transport with capability-visible failure; no silent Connect/offline fallback.
- IPv4/IPv6 packet construction and parsing, TCP/UDP/ICMP/ICMPv6, ARP/NDP primitives, VLAN and bounded IPv6 extension parsing.
- Bounded schedulers with active-work limits and deterministic result ordering.
- Retry support, RTT estimator, congestion controller, adaptive scheduler, scan metrics, cancellation, and RAII cleanup.
- Offline stress/benchmark infrastructure and a privileged dual-stack namespace CI lab.
- Current privileged CI verifies IPv4/IPv6 SYN open/closed results against Nmap and ACK reset/drop/administrative-reject behavior in an isolated namespace.

## Architecture observations

### Correlation

The shared `net::CorrelationKey` currently contains target identity, source/destination ports, and a 32-bit sequence. The transport layer performs additional validation in several paths, but the correlation table contract itself does not encode all of the identity required by the Core V3 target model.

Missing from the reusable key contract include, where applicable:

- explicit transport protocol
- local/source and remote/destination typed addresses as separate identities
- interface identity
- IPv6 scope
- scan generation / probe generation
- TCP acknowledgement expectations
- quoted-packet identity metadata

This is not changed in CORE-01; it is a concrete CORE-03 target.

### Port-state model

The current canonical states are:

`OPEN`, `CLOSED`, `FILTERED`, `UNKNOWN`, `OPEN_OR_FILTERED`, `UNFILTERED`, `ERROR`, and `UNREACHABLE`.

The requested Core V3 specification also calls for `CLOSED_OR_FILTERED`. Existing timeout and unreachable semantics therefore require a formal review before changing the enum. This belongs in CORE-02.

TCP Connect currently performs bounded confirmation for negative/refused/timeout/socket-error observations and degrades contradictory negative evidence to `UNKNOWN/CONFLICTING_EVIDENCE`. SYN RST evidence is currently treated as definitive. These behaviors need to be captured in the formal state specification rather than changed ad hoc.

### Timing and retries

`RttEstimator` already implements bounded SRTT/RTTVAR/RTO-style behavior for valid response samples. It currently has no loss estimator and no per-target/per-network scope in the estimator itself.

`CongestionController` maintains bounded global parallelism with timeout backoff, response recovery, and an EWMA-like drop-rate signal. It does not yet model per-host/per-group concurrency, queue pressure, retry pressure, or transport-error feedback.

`PortScanScheduler` has delayed retries and conflict-aware negative confirmation. Retry delay/count remain configuration/profile driven; a complete evidence-driven retry policy is CORE-07.

### Scheduling and backpressure

Port scanning uses a single queue plus pending map and delayed-retry map. Retries are reinserted at the front. This is bounded by `max_outstanding`, but there is no demonstrated per-host fairness policy.

Discovery uses a stricter admission check: requested work is rejected when current pending + queued + requested exceeds `max_outstanding`. That makes `max_outstanding` both a concurrency bound and a total-admission bound for that path, which is a scalability/semantics issue to revisit in CORE-09/CORE-12.

The adaptive scheduler and port/UDP/discovery schedulers each own related timeout/retry/concurrency logic. Do not merge or rewrite them merely for symmetry; first establish state and timing contracts, then remove duplicated policy only where a single coherent abstraction is proven useful.

## Ground-truth lab gap

The repository already has a useful privileged CI namespace, but it is not yet the requested Core V3 ground-truth lab.

Current coverage is narrow:

- one Linux namespace target
- dual-stack open/closed TCP SYN checks
- Nmap comparison
- ACK reset/drop/administrative-reject checks
- packet capture for one IPv4 validation path

Missing CORE-01 capabilities:

- reusable independent truth manifest/controller
- deterministic network fault profiles
- 0/1/5/10/20% loss scenarios
- delay/jitter/duplication/reordering/burst-loss/bandwidth profiles
- RTT profiles up to 800 ms
- explicit RST/ICMP rate-limit scenarios
- reusable truth snapshots of listeners, firewall rules, qdisc state, and packet evidence
- a lab interface intended for later UDP/discovery/differential phases

CORE-01 should extend the existing safety model rather than replace the current CI harness.

## Packet-engine observations

The project already has strict bounded parsing, checksum validation, malformed/truncation handling, and fuzz coverage across major packet families. CORE-10/11 should be audits plus adversarial regression expansion, not packet-stack rewrites.

## Benchmark observations

The offline benchmark is useful for algorithmic regression and already covers target expansion, parsers, correlation, timers, schedulers, orchestration, matching, and serialization. Historical records are machine-specific and explicitly not live-network throughput claims.

There is not yet a Core V3 benchmark whose authoritative primary metric is correct-results-per-second against independent ground truth. There is also no general Nmap differential harness that treats the truth controller—not Nmap—as the oracle. Those are CORE-17 and CORE-19.

## Highest-priority risks

1. The existing private lab is too narrow to validate loss resilience or false-definitive-state guarantees.
2. Shared correlation identity is weaker than the requested V3 contract.
3. Port-state semantics are implemented but not formally specified as one authoritative state machine.
4. Timing/congestion signals are globally scoped and do not yet drive the full retry/rate policy.
5. Queue admission/fairness semantics differ across schedulers.
6. Historical benchmark throughput cannot support superiority claims.
7. Long-run leak/cancellation gates are not yet demonstrated for 24h/72h workloads.

## Ordered execution decision

The roadmap order remains correct:

1. CORE-01 ground-truth lab
2. CORE-02 formal port-state specification
3. CORE-03 correlation V3
4. CORE-04 evidence-to-state engine
5. fault injection, timing, retry, congestion, scheduler/backpressure
6. packet/discovery/UDP audits
7. fuzz/stress/massive scheduling
8. profiling and measured I/O optimization
9. Nmap differential harness
10. long-run reliability gate

No performance optimization or new scan family should precede those correctness gates.
