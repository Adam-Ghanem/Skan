# Skan Phase 0–14 Engineering Audit

## Scope and conclusion

This audit reviewed the Phase 0–14 implementation, including the core model, single-reactor I/O path, packet parsers, discovery and port schedulers, service and OS detection, adaptive timing, Linux transport/capture, output, CLI, orchestration, tests, documentation, and Makefile. The implementation remains a **Nmap-inspired, Linux-first network-scanning engine** rather than an Nmap-compatible replacement. The audit found and repaired concrete lifecycle, correlation, parsing, output, and scalability defects without introducing a new reactor, worker threads, a second target subsystem, or a second result/output model.

The final code preserves the existing explicit-target and capability-gated design. Raw Linux tests still report `SKIPPED` when AF_PACKET permission is unavailable, while an explicitly requested live Linux scan fails clearly rather than falling back to offline behavior.

## A. Architecture findings

The dependency direction is coherent. `core` supplies shared value types, the packet layer is below discovery and scanning, schedulers own bounded logical work, transports own descriptor and byte movement, detection consumes prior result types, and the Phase 11 orchestrator coordinates these pieces. The project uses one `io::IOEngine` per `ScanSession`; no thread, sleep loop, polling loop, or secondary event reactor was found in production code.

Ownership is predominantly RAII-based. Descriptors are held by move-only network wrappers or connection destructors, events are borrowed by the reactor under an explicit lifetime contract, schedulers own pending work, and the orchestrator releases active stages through their existing cancellation and destructor paths. The explicit target model remains `core::Target`/`core::Host`; Phase 11 does not add a duplicate hostname, CIDR, range, or mixed-target parser.

## B. Critical correctness and memory-safety findings

| Finding | Resolution | Evidence |
| --- | --- | --- |
| Epoll records carried stale raw event pointers. A callback could remove or destroy another event while its readiness record remained in the same `epoll_wait` batch. | Added opaque per-registration tokens and lookup/revalidation before and after callbacks. Stale records are ignored without dereferencing the old event. | `include/io/event.hpp`, `include/io/io_engine.hpp`, `src/io/io_engine.cpp` |
| A scheduler could receive timer ID zero after reactor shutdown or timer-allocation failure and leave a probe pending with no timeout callback. | Added explicit zero-timer handling in port, service, OS, and adaptive schedulers. Affected logical work becomes terminal with an internal error or failed state. | `src/portscan/port_scheduler.cpp`, `src/detect/service_scheduler.cpp`, `src/osdetect/os_scheduler.cpp`, `src/scanengine/adaptive_scheduler.cpp` |
| Linux SYN transport cleared pending submissions without clearing correlation entries during close/reopen. | Added `CorrelationTable::clear()` and call it during transport teardown. | `include/net/packet_filter.hpp`, `src/net/packet_filter.cpp`, `src/net/network_scan_transport.cpp` |
| Packet parsing accepted an arbitrary caller-supplied maximum and could copy spans larger than the Ethernet maximum. | Clamped `PacketReceiver` parsing to 65,535 bytes before retaining raw frame data. | `src/net/packet_receiver.cpp` |
| Valid future/unknown TCP option kinds were treated as malformed, unnecessarily discarding otherwise usable responses. | Unknown options are skipped with strict length and alignment checks; recognized options remain exposed through the public model. | `src/packet/tcp.cpp` |

## C. High-priority robustness findings

The Linux network session counter was changed from mutable process-global state to adapter-owned state, eliminating an unnecessary global lifecycle dependency. `ScanGroup` outstanding-metric arithmetic now saturates at zero, preventing underflow when queued work is cancelled before submitted work completes. `ScanMetrics` now uses incremental averaging rather than cumulative multiplication, avoiding avoidable floating-point overflow for long-running workloads. Congestion backoff protects the floating-to-`size_t` conversion boundary for very large configured parallelism.

The PacketReceiver attach/detach and close paths now have direct pipe-backed reactor tests. The existing borrowed-event contract remains explicit: callers own events and must keep them alive while registered; reactor shutdown detaches registrations but does not destroy caller-owned events.

## D. Medium-priority and lower-priority issues

The explicit target boundary is intentionally incomplete for professional hostname, CIDR, range, normalization, mixed-target, and large-scale deduplication support. This is documented as the next major subsystem rather than being hidden inside Phase 11. Live raw-packet OS fingerprinting is now implemented behind an explicit capability-gated Linux transport; injected/offline evidence collection and deterministic matching remain available when live capability is absent.

The compact project-owned service and OS databases are deliberately not broad imported fingerprint corpora. Service matching compiles regular expressions during database parsing, bounds response bytes, and does not infer identity solely from port numbers. The remaining low-priority cleanup is primarily cosmetic Makefile indentation and future API extraction for direct CLI-parser fuzzing; neither is needed for the current correctness boundary.

## E. Performance findings and repairs

Three measurable large-workload costs were addressed. Port and service schedulers no longer sort the complete result vector after every terminal completion; they mark order dirty and sort once when results are observed. `ScanReportBuilder` now indexes hosts by address rather than performing repeated linear scans for every child result. High-volume per-host/per-port events no longer copy the complete aggregated `core::Target`; lifecycle events retain the aggregate target, while item events identify the host in their message/target field.

The deterministic orchestration stress test now executes 1,000 hosts × 100 TCP ports, or 100,000 logical port operations, with injected responses and no network traffic. Additional tests exercise 10,000 same-deadline timers and 10,000 live correlation entries. These workloads completed within bounded test time after the ordering and event-copy changes.

## F. Missing capabilities and planned work

The following capabilities are intentionally not claimed as complete:

| Capability | Status |
| --- | --- |
| Explicit IPv4 target execution | Implemented |
| Hostname/CIDR/range/mixed-target resolver and normalizer | Implemented in Phase 12 with bounded synchronous A-record resolution |
| TCP Connect scanning | Implemented |
| Offline SYN probe model | Implemented |
| Explicit Linux AF_PACKET SYN transport | Capability-gated and implemented where permitted |
| ICMP/TCP/ARP discovery adapters | Offline and explicit Linux paths implemented within current scope |
| TCP stream service detection | Implemented with bounded project-owned probes |
| Live raw OS fingerprinting | Capability-gated and implemented through `LinuxOSProbeTransport`; unavailable is reported explicitly when AF_PACKET cannot open |
| Offline UDP scanning | Implemented with bounded probes, retries, correlation, and deterministic recording transport |
| Explicit Linux AF_PACKET UDP scanning | Capability-gated and implemented where permitted; no fallback |
| OS probe families and evidence aggregation | Implemented for bounded TCP, ICMP, UDP, and correlated ICMP-error evidence |
| Evasion, spoofing, exploitation, credential handling, persistence | Out of scope |

## G. Testing upgrade

The complete Makefile test graph contains 75 test-binary executions.
 New and strengthened coverage includes stale epoll batch records, PacketReceiver attach/detach and close lifecycle, oversized capture frames, unknown TCP options, closed-reactor timer failure, queued-cancellation metric arithmetic, 10,000 timers, 10,000 correlations, 1,000-host × 100-port orchestration, pipeline cancellation, discovery response handling, service/OS ordering, strict OS ranges and UDP signatures, all OS probe families, injected UDP evidence, 1,000-host/12,000-probe OS stress, structured OS output, and capability-aware Linux skips.

An optional offline libFuzzer target exercises Ethernet, IPv4, TCP, UDP, ICMP, service-database, OS-database, OS probe construction/assessment, port-selection, and timing-profile parsers. If Clang and its fuzzer runtime are unavailable, `make fuzz` reports `SKIPPED` and exits successfully; it never fabricates a fuzz result.

## H. Documentation and build findings

`README.md` and `ARCHITECTURE.md` now distinguish implemented, capability-gated, offline/injected, and planned behavior. They document the one-reactor model, explicit transport selection, partial-report cancellation, output boundary, target-engine gap, stress coverage, and fuzz behavior. The Makefile now exposes `release`, `debug`, `asan`, `ubsan`, `coverage`, and optional `fuzz` targets while retaining C++20/C11 and the existing strict warning set.

## I. Validation record

The following gates passed after the final changes:

| Gate | Result |
| --- | --- |
| Clean production build | Passed |
| Complete release test suite | Passed; 75 binaries executed |
| Debug build | Passed |
| AddressSanitizer with leak detection | Passed |
| UndefinedBehaviorSanitizer | Passed |
| Coverage target | Passed |
| Release target | Passed |
| Optional fuzz target | Clean `SKIPPED`; Clang unavailable in the environment |
| CLI version/help and offline output matrix | Passed |
| Linux capability failure behavior | Passed; explicit failure/unavailable evidence, no fallback |
| Phase 14 OS database and matcher behavior | Passed; ranges, UDP signatures, optional metadata, and presence rules |
| Phase 14 OS probe stress | Passed; 1,000 hosts and 12,000 deterministic probes; direct typed-probe, structured-output, and capability-aware transport tests |
| `git diff --check` | Passed before commit |

AF_PACKET-dependent tests were skipped because the execution environment returned `Operation not permitted`. No raw-network test was marked as a successful live test under that limitation.

## J. Recommended upgrade order

The next target-related upgrade should replace the current synchronous platform resolver with an asynchronous implementation behind the existing injectable `HostnameResolver` boundary if hostname resolution latency becomes material. The existing parser, CIDR/range expansion, canonicalization, deduplication, explicit limits, and numeric ordering should remain unchanged.

Broader protocol coverage, larger corpus management, and optional scripting should follow only after their ownership and resource limits are specified. Phase 14 intentionally does not claim IPv6, evasion, spoofing, decoys, fragmentation, credentials, exploitation, UDP service inference, or public-target scanning. Performance work should continue with measured benchmarks for target expansion, packet parsing, correlation, queue operations, matching, and output serialization rather than speculative rewrites.

## References

[1]: include/io/io_engine.hpp "IOEngine public ownership and lifecycle contract"
[2]: src/io/io_engine.cpp "Tokenized epoll dispatch and timer implementation"
[3]: src/orchestrator/scan_pipeline.cpp "Unified Phase 11 pipeline"
[4]: src/orchestrator/scan_report_builder.cpp "Canonical report mapping and host indexing"
[5]: Makefile "Build, test, sanitizer, coverage, and fuzz targets"


## K. Phase 13 UDP audit update

Phase 13 adds first-class UDP scanning without changing the established TCP/discovery/service/OS/output contracts. The new `UDPScheduler` is single-reactor and bounded: it owns a deterministic queue, pending map, fixed source-port occupancy range, one timer per active attempt, bounded retries, and cancellation-safe cleanup. It uses the existing `IOEngine`, Phase 7 timing policy, Phase 2 UDP packet composition, canonical `PortResult`, and output model rather than introducing duplicate infrastructure.

| UDP area | Audit status | Evidence |
| --- | --- | --- |
| Explicit opt-in and target handoff | Passed | `--udp` is required; Phase 12 normalized targets are reused; UDP is never enabled by default. |
| Port selection and defaults | Passed | Strict single/list/range parsing, deduplication, ten-port project-owned default set, and invalid-port rejection. |
| Probe database | Passed | Strict `data/udp-probes.db` parser with bounded hexadecimal payloads, response limits, unique names/ports, and one generic fallback. |
| Datagram classification | Passed | Correlated response is `OPEN`; malformed/oversized data is `ERROR`; silence is `OPEN_OR_FILTERED`, never `CLOSED`. |
| ICMP error classification | Passed | ICMPv4 Destination Unreachable is checksum and bounds validated; code 3 is `CLOSED`; administrative/network evidence is `FILTERED`. |
| Correlation and lifecycle | Passed | Logical IDs plus local/target IPv4 and source/destination ports are checked; unrelated, duplicate, and late responses cannot complete unrelated work. |
| Offline test seam | Passed | `RecordingUDPTransport` supports deterministic injected responses and no network access. |
| Linux raw UDP | Capability-gated | `LinuxUDPScanTransport` reuses Linux transport/capture/receiver and the shared reactor; it fails explicitly and does not fall back when AF_PACKET is unavailable. |
| Service and OS interactions | Deliberately limited | TCP service detection receives TCP results only; OS detection filters back to TCP; no UDP service or OS inference is fabricated. |

The expanded tests include malformed ICMP and embedded packet truncation, strict UDP database failures, response classification, retries, timeout state, duplicate/unrelated response isolation, pipeline ordering, ten-thousand-operation host/port coverage, one-hundred-thousand-operation offline coverage, and a Linux raw capability test that reports `SKIPPED` on hosts without AF_PACKET permission. The fuzz entry point now exercises UDP port/probe-database parsing and OS probe construction/assessment alongside the existing bounded packet parsers.

The remaining UDP limitations are intentional: IPv6 is not implemented, Linux live results depend on host AF_PACKET and interface neighbor capabilities, UDP protocol/service matching is absent, and UDP data is not used for OS fingerprinting. The implementation makes no claim of evasion, spoofing, fragmentation, credentials, exploitation, or public-target safety beyond the existing explicit-target and capability boundaries.


## K. Phase 14 live OS fingerprinting audit update

Phase 14 adds live-capable OS fingerprinting through the existing typed probe, scheduler, matcher, packet, capture, correlation, and report boundaries. The implementation is explicit about capability: offline and injected modes remain deterministic, Linux mode requires a selected interface and AF_PACKET permission, and Connect mode is not reinterpreted as a packet OS transport.

| Area | Audit status | Evidence |
| --- | --- | --- |
| Probe families | Passed | TCP SYN/ACK/FIN/NULL/XMAS, closed variants, ICMP Echo, UDP fingerprint, and UDP Port Unreachable are typed, bounded, and scheduled through the shared reactor. |
| Packet composition | Passed | Linux submissions use existing `packet::Packet` composition and the existing IPv4/TCP/UDP/ICMP serializers. |
| Capture and correlation | Passed | Outer and embedded packet fields are validated; TCP acknowledgment, UDP reversed ports, and ICMP quoted transport fields are checked before delivery. |
| Database | Passed | `data/os-fingerprints.db` supports optional metadata, typed exact values, bounded ranges, UDP signatures, response presence, and strict duplicate/invalid input rejection. |
| Matching | Passed | Available evidence is weighted deterministically; absent, timeout, unsupported, and unavailable fields do not fabricate a match or incur false penalties. |
| Result propagation | Passed | `OSDetectionResult` is retained per host alongside legacy match vectors and is serialized in normal, JSON, XML, and grepable formats. |
| Linux capability boundary | Passed | Permission, not-supported, interface, capture, and send failures are explicit `UNAVAILABLE` evidence; no offline fallback occurs. |
| Stress and safety | Passed | Deterministic injected tests cover 1,000 hosts and 12,000 probes, cancellation, timeout, malformed, duplicate, and unrelated evidence. |

The remaining limitations are intentional. Phase 14 is IPv4-only, uses a small project-owned fingerprint dataset rather than a broad corpus, does not implement UDP service inference, does not add evasion or spoofing, and does not generate public-target traffic. AF_PACKET tests remain environment-dependent and report `SKIPPED` when the sandbox returns `Operation not permitted`; this is not counted as live-network success.


## L. Post-Phase-14 deep audit

This follow-up audit was performed against revision `2a9e992b20e0e12dcee430a5e8169f6f443621e1` and the focused hardening changes in the working tree. The audit covered the reactor, timers, packet parsers, capture receiver, transports, schedulers, target expansion, orchestration, output, benchmark behavior, ownership boundaries, and the public capability surface. Nmap was not installed in the sandbox, so the comparison uses the official Nmap Reference Guide rather than an invented local runtime measurement.

### L.1 Findings and repairs

| Finding | Severity | Resolution | Verification |
| --- | --- | --- | --- |
| `PacketReceiver` passed the full IPv4 transport span to the UDP parser instead of the UDP header-declared datagram span. Valid packets with bounded IPv4 padding could therefore be rejected by a strict UDP checksum calculation. | High | Parse `transport.first(udp_length)` after validating the declared length, and add a regression with valid trailing IPv4 padding. | `tests/unit/net/test_packet_receiver.cpp`; targeted test passed |
| `PacketReceiver::close()` could retain a logical event after reactor shutdown if the descriptor had already been detached. | High | Treat a stale `NotFound`/unregistered event as detached, reset receiver ownership, and close capture safely. | Shutdown-before-close regression passed |
| Pipeline output-file writes serialized directly into the destination, risking truncation if later writing failed. | High | Serialize fully in memory, write through a securely created same-directory temporary file, flush and `fsync`, then rename atomically. | Pipeline output-file regression passed |
| Service duplicate suppression used a linear scan over all prior target/port pairs. | Medium | Replace it with a hashed composite target/port key while preserving first-seen ordering. | Service scheduler suite passed; 10,000-target benchmark completed |
| Target normalization performed a redundant second deduplication pass after expansion had already guaranteed uniqueness. | Low | Move the expansion vector directly into the normalized target set and retain the canonical numeric sort. | Target-engine suite passed |
| User-supplied service databases had no explicit aggregate byte, line, probe, rule, or regex-pattern limits. | Medium | Bound service database input to 1 MiB, lines to 16 KiB, probes and rules to 256 each, and patterns to 4 KiB before regex compilation. | New parser regressions passed; normal builds remain warning-free |
| The benchmark passed a temporary OS database to a scheduler whose public contract borrows the database. This was a benchmark lifetime error, not a production-orchestrator defect, but it surfaced as an ASan stack-use-after-scope. | High in test harness | Keep the database in a named local object for the scheduler lifetime and document the borrowed-database contract in both low-level scheduler headers. | ASan/LSan benchmark run passed; production detectors already own databases by value |

No defect was found requiring a second reactor, a worker thread, polling, a sleep-based timing loop, a second packet serializer, or a live-network fallback. The low-level schedulers remain intentionally non-owning with respect to their databases; the new header comments make this lifetime requirement explicit, while the owning detector wrappers remain the preferred public integration path.

### L.2 Architecture and safety assessment

The reactor boundary remains coherent. Production event multiplexing is centralized in `IOEngine` using epoll; timers are represented by the existing timer mechanism; transport descriptors are attached through existing event ownership; and callbacks revalidate opaque registration tokens before dereferencing events. The audit found no production `std::thread`, `pthread`, `std::async`, `poll`, `select`, `sleep`, or additional epoll reactor outside the existing `IOEngine` implementation.

The packet boundary remains coherent. IPv4 total length is validated before transport dispatch, UDP length is validated before parsing, TCP data offsets and recognized option lengths are bounded, and ICMP checksums are verified. Unknown TCP options are skipped with alignment checks rather than being treated as malformed solely because they are not represented in the compact public model. The project still does not claim IPv6 parsing or scanning.

The primary remaining API caveat is borrowed database lifetime in direct `OSScheduler` and `ServiceScheduler` construction. It is now documented; direct callers must keep the database alive, and callers needing ownership should use `OSDetector` or `ServiceDetector`. Converting those low-level schedulers to value ownership would cause avoidable copies and broader API churn, so it is not included in this focused audit change.

### L.3 Scoped Nmap comparison

Nmap’s official guide describes a broader network exploration tool with host discovery, numerous TCP/UDP/SCTP/IP-protocol scan types, service/version probing, OS detection, NSE scripting, adaptive timing, multiple output formats, and advanced features such as traceroute and local-link ARP/IPv6 Neighbor Discovery [6] [7] [8]. Its OS detector compares many TCP/IP response properties against a database described as containing more than 2,600 known fingerprints [9]. Nmap’s service/version subsystem uses a much larger probe and match corpus with intensity controls [10].

| Capability area | Skan after Phase 14 | Nmap documented capability | Audit conclusion |
| --- | --- | --- | --- |
| IPv4 target parsing and bounded expansion | IPv4 address, CIDR, range, hostname A-record resolution, mixed-target deduplication, explicit limits | Broad target specification and host-group controls | Skan is intentionally narrower but explicit and bounded |
| Host discovery | Offline and explicit Linux ICMP/TCP/ARP paths in current scope | ICMP, TCP SYN/ACK, UDP, SCTP, IP protocol, ARP/ND, list scan, no-ping | Skan covers a bounded subset and must not claim Nmap parity |
| TCP scanning | Connect and explicit Linux SYN path, with canonical port states | Connect, SYN, FIN, NULL, Xmas, ACK, Window, Maimon, custom flags, idle, and more | Skan covers only its implemented safe subset |
| UDP scanning | Offline and capability-gated Linux UDP with bounded project-owned probes | UDP scan with broader payload corpus, rate-limit handling, and version-assisted disambiguation | Skan has honest bounded UDP coverage but no Nmap-scale corpus or inference |
| SCTP/IP protocol scans | Not implemented | SCTP INIT/COOKIE-ECHO and IP protocol scan | Planned only if a future scope explicitly requires them |
| Service/version detection | Bounded project-owned TCP probes and matcher | Large probe/match corpus, intensity, RPC and SSL behavior | Skan is a compact inventory detector, not a version-detection replacement |
| OS fingerprinting | IPv4 TCP/ICMP/UDP typed probes, small project-owned database, explicit Linux capability gate, deterministic injection | Dozens of tests, broad OS database, device/CPE classification, fuzzy guesses and auxiliary TCP/IP tests | Skan is capability-honest but materially narrower |
| Timing and parallelism | Single reactor, bounded outstanding work, retries, adaptive timing controller | Adaptive parallelism, host groups, RTT bounds, retries, host/script timeouts, rates, timing templates [11] | Skan has the right architectural seam but fewer controls |
| Output | Normal, JSON, XML, grepable, structured OS status, atomic file replacement | Interactive/normal, XML, grepable, script-kiddie, append/clobber, resume [12] | Skan provides the required canonical formats for its scope |
| Scripting and extensibility | No scripting engine | Lua NSE with discovery, version, vulnerability, and extensibility workflows [13] | Deliberately out of scope; not a hidden gap |
| IPv6 | Not implemented | IPv6 support and Neighbor Discovery paths | Explicit roadmap item only if required |
| Evasion/spoofing/exploitation | Not implemented and intentionally prohibited by scope | Nmap documents decoys, fragmentation, idle/FTP-bounce and scripting capabilities | Skan must not add these without a separate safety and authorization design |

This comparison is a scope matrix, not a claim that Skan should reproduce Nmap. Skan’s strongest differentiators are its narrow explicit capability boundary, one-reactor design, deterministic offline injection, bounded resource policies, and refusal to fabricate live results when AF_PACKET capability is absent.

### L.4 Benchmark summary

The reproducible offline harness reports five-sample median and p95 timings for 100, 1,000, and 10,000 targets. Full measurements are in [`BENCHMARKS.md`](BENCHMARKS.md). At 10,000 targets, target expansion completed in 0.398 ms median, TCP/UDP/service scheduler stages completed in 42.488/41.082/45.431 ms, the twelve-probe-per-target OS stage completed in 544.160 ms for 120,000 logical probes, full single-TCP-port orchestration completed in 100.455 ms, JSON serialization in 5.540 ms, and XML serialization in 2.439 ms. Peak process RSS was 54,044 KiB after the OS stage. All benchmark workloads were offline and used documentation-space addresses.

The benchmark demonstrates approximately linear growth over the tested range. The OS stage is the dominant intentional cost because it performs twelve logical probes per host and retains evidence for matching. In the refreshed run, the 10,000-target OS stage completed in 544.160 ms median and the full single-TCP-port orchestrator completed in 100.455 ms median, with 54,044 KiB peak RSS observed after the OS stage. These measurements are regression baselines on the sandbox host, not universal network-performance claims. Nmap’s own guide emphasizes adaptive parallelism, timeout, retry, host-group, rate, and timing controls as major performance factors [11], so live-network comparisons would not be meaningful without identical targets, privileges, interfaces, timing policies, and result requirements.

### L.5 Prioritized next-phase roadmap

| Priority | Candidate work | Rationale and acceptance boundary |
| --- | --- | --- |
| P1 | Async hostname resolution behind the existing `HostnameResolver` seam | Avoid blocking the single reactor when DNS latency matters; preserve IPv4-only, bounded result count, deterministic ordering, and injectable tests. |
| P1 | Broaden OS corpus and response model only with project-owned data and explicit provenance | Improve identification quality without importing Nmap’s database; add corpus validation, confidence calibration, and unknown/insufficient-evidence semantics. |
| P1 | Add live-network integration in a controlled lab environment | Validate AF_PACKET send/capture and neighbor behavior with an explicit interface and private fixtures; never convert capability failure into offline fallback. |
| P2 | Add measured output-path and report-builder profiling | Reduce avoidable copying/sorting only after profiling; retain canonical ordering and all four output contracts. |
| P2 | Add direct CLI parser fuzzing and long-run cancellation/resource tests | Exercise malformed options, extreme target limits, repeated cancellation, timer exhaustion, and output-path failures without public traffic. |
| P2 | Expand TCP/UDP protocol coverage within the existing packet layer | Consider additional safe scan semantics or UDP service evidence only with typed models, strict correlation, bounded payloads, and canonical `PortResult` states. |
| P3 | IPv6 architecture and implementation | Requires new IPv6 packet, ICMPv6, Neighbor Discovery, target, capture, database, and output semantics; do not begin piecemeal. |
| P3 | Optional scripting/extensibility | Requires a separate sandbox, resource, authorization, and output design; it is not a small Phase 15 patch and is intentionally not started. |

No Phase 15 implementation was started by this audit.

## M. Additional references

[6]: https://nmap.org/book/man.html "Nmap Reference Guide"
[7]: https://nmap.org/book/man-host-discovery.html "Nmap Host Discovery"
[8]: https://nmap.org/book/man-port-scanning-techniques.html "Nmap Port Scanning Techniques"
[9]: https://nmap.org/book/man-os-detection.html "Nmap OS Detection"
[10]: https://nmap.org/book/man-version-detection.html "Nmap Service and Version Detection"
[11]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"
[12]: https://nmap.org/book/man-output.html "Nmap Output"
[13]: https://nmap.org/book/nse.html "Nmap Scripting Engine"
