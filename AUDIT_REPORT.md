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

Broader protocol coverage, larger corpus management, and optional scripting should follow only after their ownership and resource limits are specified. Phase 15 now implements the typed IPv6 foundation and bounded dual-stack offline/Connect paths; it still does not claim native Linux raw IPv6, complete ND, IPv6 OS fingerprinting, evasion, spoofing, decoys, fragmentation, credentials, exploitation, UDP service inference, or public-target scanning. Performance work should continue with measured benchmarks for target expansion, packet parsing, correlation, queue operations, matching, and output serialization rather than speculative rewrites.

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

The remaining UDP limitations are intentional: offline IPv6 packet construction and family-aware correlation are implemented, but Linux live raw IPv6 remains unavailable; UDP protocol/service matching is absent, and UDP data is not used for OS fingerprinting. The implementation makes no claim of evasion, spoofing, fragmentation, credentials, exploitation, or public-target safety beyond the existing explicit-target and capability boundaries.


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

The remaining limitations are intentional. Live OS probe execution remains IPv4-only and uses a small project-owned fingerprint dataset rather than a broad corpus; IPv6 OS detection is structured `UNAVAILABLE`, UDP service inference is absent, evasion/spoofing are prohibited, and no public-target traffic is generated. AF_PACKET tests remain environment-dependent and report `SKIPPED` when the sandbox returns `Operation not permitted`; this is not counted as live-network success.


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

The packet boundary remains coherent. IPv4 total length is validated before transport dispatch, UDP length is validated before parsing, TCP data offsets and recognized option lengths are bounded, ICMP checksums are verified, and IPv6 base/extension lengths are bounded before transport dispatch. Unknown TCP options are skipped with alignment checks rather than being treated as malformed solely because they are not represented in the compact public model. IPv6 parsing and offline/Connect scanning are implemented; native Linux raw IPv6 scanning remains unavailable.

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
| P1 | Async hostname resolution behind the existing `HostnameResolver` seam | Avoid blocking the single reactor when DNS latency matters; preserve typed A+AAAA bounds, deterministic ordering, and injectable tests. |
| P1 | Broaden OS corpus and response model only with project-owned data and explicit provenance | Improve identification quality without importing Nmap’s database; add corpus validation, confidence calibration, and unknown/insufficient-evidence semantics. |
| P1 | Add live-network integration in a controlled lab environment | Validate AF_PACKET send/capture and neighbor behavior with an explicit interface and private fixtures; never convert capability failure into offline fallback. |
| P2 | Add measured output-path and report-builder profiling | Reduce avoidable copying/sorting only after profiling; retain canonical ordering and all four output contracts. |
| P2 | Add direct CLI parser fuzzing and long-run cancellation/resource tests | Exercise malformed options, extreme target limits, repeated cancellation, timer exhaustion, and output-path failures without public traffic. |
| P2 | Expand TCP/UDP protocol coverage within the existing packet layer | Consider additional safe scan semantics or UDP service evidence only with typed models, strict correlation, bounded payloads, and canonical `PortResult` states. |
| P3 | Native Linux IPv6 raw capability | Remains explicitly unavailable until a separately reviewed, explicit-interface capture/injection implementation and controlled lab acceptance exist; current Phase 16 behavior remains unavailable with no fallback. |
| P3 | Optional scripting/extensibility | Requires a separate sandbox, resource, authorization, and output design; it is not a small Phase 15 patch and is intentionally not started. |

Phase 15 implementation was audited above; Phase 16 is complete within the capability boundary documented in the addendum below.

## M. Additional references

[6]: https://nmap.org/book/man.html "Nmap Reference Guide"
[7]: https://nmap.org/book/man-host-discovery.html "Nmap Host Discovery"
[8]: https://nmap.org/book/man-port-scanning-techniques.html "Nmap Port Scanning Techniques"
[9]: https://nmap.org/book/man-os-detection.html "Nmap OS Detection"
[10]: https://nmap.org/book/man-version-detection.html "Nmap Service and Version Detection"
[11]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"
[12]: https://nmap.org/book/man-output.html "Nmap Output"
[13]: https://nmap.org/book/nse.html "Nmap Scripting Engine"


## N. Phase 15 IPv6 and dual-stack audit update

Phase 15 extends the existing single-reactor architecture with a typed binary IPv4/IPv6 identity and bounded dual-stack execution. No second packet stack, scheduler, reactor, worker thread, polling loop, sleep, implicit interface selection, or fallback path was introduced.

| Area | Audit status | Evidence and boundary |
| --- | --- | --- |
| Typed identity | Passed | `core::IpAddress` carries family and binary bytes through targets, hosts, submissions, correlation, aggregation, and reports; IPv4 and IPv6 cannot cross-match. |
| Target Engine | Passed | IPv4/IPv6 literals, CIDR, ranges, comma-separated mixtures, bounded A+AAAA resolution, binary deduplication, canonical formatting, and deterministic family-aware ordering. |
| IPv6 packet model | Passed | Strict 40-byte base-header validation and serialization with payload bounds, traffic class, flow label, next-header, hop-limit, and binary addresses. |
| IPv6 extensions | Passed within scope | Hop-by-Hop, Routing, Fragment, and Destination Options are recognized under header-count and byte budgets with malformed/unsupported/limit states; no extension attack generation or complete fragment reassembly is claimed. |
| Checksums and ICMPv6 | Passed within scope | Shared IPv6 pseudo-header accumulation supports TCP, UDP, and ICMPv6; Echo, bounded error messages, and limited ND forms are parsed/serialized safely. |
| PacketReceiver and filtering | Passed | EtherType `0x86DD`, bounded extension dispatch, typed IPv6 observations, and family-aware filters/correlation reuse the existing receiver and table boundaries. |
| AF_INET6 Connect/service | Passed | Existing nonblocking event/timer lifecycle supports AF_INET6 loopback; bounded TCP service detection uses the same transport path. |
| Offline discovery/UDP | Passed | Existing schedulers and recording seams construct IPv6 ICMP/TCP/UDP probes and correlate injected typed responses; UDP silence remains `OPEN_OR_FILTERED`. |
| Linux raw IPv6 | Explicitly unavailable | Existing raw Linux adapters remain IPv4/ARP-specific and require an explicit interface; IPv6 requests fail clearly without fallback or fabricated success. |
| IPv6 OS detection | Explicitly unavailable | The orchestrator returns `UNAVAILABLE` with zero confidence for IPv6-containing targets; no address/port/service-derived identity is emitted. |
| Output and CLI | Passed | Canonical host results and JSON/XML/grepable output expose `family`; `resolve`, `scan`, and offline `discover` accept canonical IPv6 and mixed targets. |
| Safety | Passed | Tests and smoke checks use loopback, documentation-space, synthetic, or injected data only; no public-target traffic, evasion, spoofing, credentials, exploitation, or persistence exists. |

The environment continued to lack AF_PACKET permission, so raw Linux tests remained clear `SKIPPED` cases with `Operation not permitted`. The optional libFuzzer target also remained a clear `SKIPPED` case because `clang++` is unavailable; the harness itself is extended with IPv6, extension, ICMPv6, PacketReceiver, and typed-address entry points.


## O. Phase 16 production dual-stack verification addendum

Phase 16 was implemented on top of the existing Phase 0–15 architecture. The historical Phase 15 findings remain preserved above; this addendum records their Phase 16 resolution status and the final capability boundary.

| Finding or area | Phase 16 result | Evidence and boundary |
| --- | --- | --- |
| Typed scoped IPv6 identity | Resolved within scope | Shared `core::parse_ip_address` accepts one strict `%zone` token, preserves it in `IpAddress`, canonical text, equality, ordering, hashing, target expansion, Connect/service construction, and output. Numeric and named zones require explicit resolvable interface metadata for live link-local use. |
| Target resource ceilings | Resolved | `TargetLimits` and CLI paths reject values above 1,000,000 targets or 4,096 hostname results; resolver reservation is bounded and expansion remains checked before materialization. |
| TCP/UDP receive integrity | Resolved within protocol scope | PacketReceiver validates IPv4/IPv6 TCP and UDP pseudo-header checksums. IPv4 UDP checksum zero is accepted; IPv6 UDP checksum zero is malformed. Odd-length payloads and IPv6 extension-chain vectors are covered. |
| ICMPv6 quoted UDP correlation | Implemented offline/injected | A bounded shared IPv6/extension/UDP quote parser validates identity and ports. ICMPv6 Destination Unreachable code 4 maps to UDP closed evidence; malformed, unsupported, unrelated, duplicate, and late quotes do not create results. |
| Interface inventory | Resolved | Existing `NetworkInterface` now carries typed IPv6 addresses with link-local scope and separate IPv6 capture/injection capability fields. `interfaces` normal and JSON output expose the fields deterministically. |
| AF_INET6 Connect and service detection | Resolved | Existing single IOEngine/event/timer lifecycle supports scoped and unscoped AF_INET6 stream construction; local `::1` HTTP-like and SSH-like service fixtures pass when IPv6 loopback is available. |
| Offline and orchestrated dual-stack behavior | Resolved within scope | Shared discovery/port/UDP/service/OS/orchestrator/output contracts remain in use. Mixed-family stage and 10,000-host IPv6/mixed UDP scheduler workloads are deterministic and bounded. |
| Fuzz and benchmark coverage | Extended | The offline fuzz harness covers core scoped parsing and quoted IPv6 parsing. The benchmark contains IPv6 expansion, IPv6 receiver parsing, and mixed UDP scheduler rows. `make fuzz` remains a clean environmental skip when `clang++` is unavailable. |
| Native Linux raw IPv6 | Explicitly unavailable | Linux discovery, raw SYN, and raw UDP adapters remain IPv4/ARP-specific because a complete explicit-interface IPv6 source/neighbor/capture/injection path was not safely completed. IPv6 raw requests fail clearly without fallback. |
| Complete ND and IPv6 OS detection | Explicitly unavailable | Limited ICMPv6 ND parsing is not represented as a state machine. IPv6 OS results remain structured unavailable with zero confidence; no identity is inferred from address, port, service, or local platform. |

The complete registered test suite passed after the Phase 16 changes. AF_PACKET-dependent tests continued to skip cleanly with `Operation not permitted` in the sandbox. The final build, sanitizer, coverage, fuzz, benchmark, CLI capability matrix, output validation, whitespace, and prohibited-API gates are recorded with their exact results in the Phase 16 delivery record. No public target was contacted and no evasion, spoofing, exploitation, credential, persistence, or stealth path was introduced.


## P. Phase 17 native IPv6 completion record

Phase 17 extends the existing Phase 0–16 architecture rather than introducing a parallel scanner path. The Linux discovery, TCP SYN, UDP, and OS-probe adapters now accept typed IPv4 or IPv6 submissions, select sources only from the explicitly configured interface, compose IPv6 frames through the shared packet model, and correlate captured responses through the existing PacketReceiver and pending maps. The orchestrator no longer rejects IPv6 targets before these adapters are opened.

| Area | Phase 17 result | Boundary and evidence |
| --- | --- | --- |
| Native IPv6 discovery/SYN/UDP/OS branches | Family-aware branches implemented in existing adapters | AF_PACKET capability, explicit-interface source selection, capture, composition, and exact family-aware correlation share the existing IOEngine lifecycle. Sandbox runs report `Operation not permitted` when AF_PACKET is unavailable; non-loopback IPv6 Ethernet transmission still requires an explicit destination MAC or supplied neighbor path. |
| IPv6 OS evidence | Typed live/injected evidence path; matching is IPv4-only today | OS probe build/assessment supports ICMPv6 Echo, IPv6 UDP/ICMPv6 quoted UDP, and IPv6 TCP responses; evidence requires exact typed source/destination identity, carries an explicit family tag, rejects mixed-family aggregates, and does not match the IPv4-only built-in database. |
| Link-local scopes | Hardened | Named and numeric zones resolve through the shared scope matcher and must match the explicitly configured interface. No interface is selected implicitly. |
| Neighbor Discovery packet model | Strict packet primitives implemented; automatic resolver deferred | Neighbor Solicitation/Advertisement targets and options are bounded, serialized, validated, and mapped to solicited-node/Ethernet multicast addresses. There is no implicit asynchronous neighbor cache/state machine; unresolved non-loopback transmit returns an explicit capability/routing-unavailable result. |
| Non-loopback neighbor resolution | Explicit capability boundary | Without an explicit destination MAC or complete interface-local neighbor-resolution path, native non-loopback IPv6 Ethernet transmission returns a capability/routing-unavailable result instead of guessing, falling back, or generating unsolicited discovery traffic. |
| Safety and architecture | Preserved | One IOEngine, one packet layer, one receiver/correlation boundary, no threads, polling, sleeps, fallback, evasion, spoofing, exploitation, credentials, persistence, or public-target traffic. |

Deterministic unit vectors cover IPv6 OS probe construction and assessment, family-safe matching, strict Neighbor Discovery parsing, NS/NA serialization, and multicast mapping. The ordinary build and registered suite pass after the changes; AF_PACKET-dependent tests remain environmental skips with `Operation not permitted` where raw capability is unavailable. The fuzz target remains a clean environmental skip when `clang++` is unavailable.

## Q. Phase 18 production IPv6 OS fingerprinting record
Phase 18 adds production-shaped, project-owned IPv6 OS fingerprint data and integrates it into the existing bounded database, matcher, scheduler, orchestrator, and output path. The IPv6 dataset is deliberately small and generic; it is not copied from an external corpus and does not claim authoritative vendor identification.

| Area | Phase 18 result | Boundary and evidence |
| --- | --- | --- |
| IPv6 fingerprint database | Implemented | `data/os-fingerprints-v6.db` contains explicit family metadata, stable IDs, specificity, and typed TCP/UDP/ICMP-related signatures. The loader enforces bounded file, line, string, record, and signature limits and rejects duplicate names or IDs. |
| Family/protocol evidence | Implemented | TCP, UDP, ICMPv4, and ICMPv6 observations carry explicit protocol and address-family tags. Mixed aggregates become `Unknown`; incompatible records are filtered before scoring. |
| Deterministic matching | Implemented | Ranking uses confidence, specificity, display name, and stable fingerprint ID. IPv6 evidence can match only IPv6 records and cannot produce an IPv4 false positive. |
| Live IPv6 OS probes | Integrated through existing path | IPv6 TCP variants, UDP, and ICMPv6 probes use existing OSProbe, Linux capture, PacketReceiver, correlation, scheduler, and IOEngine contracts. Exact typed address and protocol correlation is required. |
| Output | Implemented | Normal, JSON, XML, and grepable output expose OS address family and selected fingerprint ID. |
| Raw Linux capability | Explicit and capability-honest | The adapter requires an explicit interface and usable AF_PACKET capture/injection plus a valid destination-MAC or interface-local neighbor path. In the sandbox, raw operations report `Operation not permitted` and do not fall back. |
| NDP | Strict packet and bounded local-link support | NS/NA parsing, serialization, options, target validation, and multicast mapping are bounded and tested. Automatic non-loopback neighbor resolution remains dependent on the selected interface’s usable neighbor capability or explicit destination MAC. |
| Offline validation | Extended | Tests cover IPv6 database metadata, oversized input rejection, IPv6 probe variants and mismatches, protocol tags, family-safe matching, outputs, NDP, fuzz entry points, and IPv6/mixed benchmark rows. |

No public-target traffic, evasion, spoofing, poisoning, exploitation, credentials, persistence, stealth, worker threads, polling, sleeps, duplicate reactors, or duplicate output pipelines were introduced.

## R. Phase 19 production network capability validation

Phase 19 audited and extended the Phase 0–18 implementation without changing the one-reactor architecture. The existing Target Engine, Scan Orchestrator, discovery, port scan, service, OS, packet, capture, correlation, timing, and output boundaries remain the only execution path.

| Area | Status | Evidence and boundary |
| --- | --- | --- |
| Typed capability engine | IMPLEMENTED | `CapabilityFact` reports `AVAILABLE`, `UNAVAILABLE`, or `UNKNOWN` with interface, family, reason, and optional diagnostic. AF_INET/AF_INET6 sockets, route-table entries, source addresses, and AF_PACKET bind are separately evidenced. |
| IPv4 capability facts | VALIDATED | Interface JSON and normal output expose AF_INET, route, source, raw capture/injection, TCP SYN, UDP, and ICMP facts. Legacy boolean fields remain compatible. |
| IPv6 capability facts | VALIDATED | Interface JSON and normal output expose AF_INET6, route, global/link-local source, raw capture/injection, ICMPv6, TCP SYN, UDP, and NDP facts. No syscall-only fact is reported as live packet capability. |
| Transport selection | IMPLEMENTED | Explicit offline, Connect, and Linux selection remains enforced. Linux raw discovery now reaches the existing IPv6 adapter after explicit interface and scope validation; unavailable capability is non-zero and never downgraded. |
| NDP | IMPLEMENTED within bounded local-link scope | Existing discovery-local NS/NA processing now uses strict target/source/MAC checks, solicited-node multicast, SLLA/TLLA validation, a 64-entry maximum cache, 30-second TTL, deterministic eviction, timer expiry, duplicate suppression, and teardown cleanup. IPv6 never uses ARP. |
| IPv6 raw SYN/UDP/discovery/OS | CAPABILITY-DEPENDENT | Existing typed packet composition, checksum, capture, exact correlation, retry, timeout, and cancellation paths remain in use. The sandbox cannot open AF_PACKET and reports `Operation not permitted`; no live success is claimed. |
| Service detection | VALIDATED offline and through existing IPv4/IPv6 Connect path | Bounded TCP HTTP/SSH-like/banner fixtures remain on the existing stream transport; no identity is inferred solely from port number. |
| OS fingerprinting | TESTED OFFLINE; CAPABILITY-DEPENDENT live | Phase 18’s project-owned IPv6 database and family-safe evidence/matcher remain integrated. Live raw OS probing requires actual interface capability and is unavailable in this sandbox. |
| Packet safety | VALIDATED | Existing frame, extension, transport, ICMPv6, quoted-packet, checksum, malformed, truncation, duplicate, late, shutdown, and bounded-allocation tests remain passing. |
| Timing/concurrency | VALIDATED | Existing one-IOEngine timers, adaptive timing, retry, cancellation, and stress coverage remain passing; no thread, polling, or sleep loop was introduced. |
| Output/observability | IMPLEMENTED | `interfaces` normal and JSON output expose typed capability facts; diagnostics remain on stderr for live failures. Existing scan writers remain deterministic and stdout-clean for structured formats. |

The restricted sandbox result is recorded as an environment limitation, not a code failure: AF_PACKET-dependent tests report `SKIPPED: ... Operation not permitted`. The optional fuzz target reports `SKIPPED` when `clang++` is unavailable. No public Internet target was contacted.

## L. Phase 20 Audit Update — Production Hardening

Phase 20 adds low-overhead ScanMetrics lifecycle, retry, byte, parser/correlation, active/peak, stage-duration, timeout, cancellation, and drop-rate observability; deadline-indexed CorrelationTable cleanup with rollback on allocation failure; reserved/deduplicated target aggregation; binary-search OS range selection; non-owning output ordering views; protocol-aware TCP/UDP service scheduling; exact structured service matches; bounded TCP/UDP/TLS-identification probes; fuzz corpus seeds; and 10,000-host output coverage.

Validation uses offline fixtures, loopback, and private documentation addresses only. The complete regression suite, 10k-host output path, service UDP/TLS identification, correlation stress, benchmark smoke, and strict-warning build passed. AF_PACKET-dependent raw paths remain capability-gated; this sandbox returns `Operation not permitted`, so raw SYN, raw UDP, raw OS, and Linux discovery are not claimed as live-validated and no fallback is used.

The service and OS corpora remain small Skan-owned datasets. TLS identifies bounded record headers/alerts and does not negotiate or audit certificates. Nmap breadth, NSE, broad fingerprints, CPE/device classification, and evasion modes remain out of scope. No Nmap source or database data was copied.

## Phase 21 Audit Record — Live-Network Hardening

The Phase 0–20 repository was audited before editing. No TODO/FIXME/HACK markers or prohibited production API matches were found in `src/` or `include/`. The existing single-reactor ownership, RAII descriptor lifecycle, typed packet parsers, deterministic target ordering, bounded schedulers, deadline-indexed correlation, and canonical output model were retained.

Implemented changes include a reusable interface preflight contract; MTU and default-route evidence; Ethernet capture/injection facts; family-aware startup and submit checks in Linux TCP SYN, UDP, discovery, and OS transports; accurate IPv6 discovery family diagnostics; saturating Phase 21 metrics; and semantic output additions across normal, JSON, XML, and grepable serializers. No capability probe transmits traffic. No fallback is selected when Linux capability is absent.

Offline validation passed for parser, scheduler, service, TLS-identification, OS-matching, metrics, output, correlation, benchmark, and CLI paths. Local Connect and loopback-safe tests run where the kernel permits them. AF_PACKET-dependent tests are `SKIPPED/UNAVAILABLE` in this sandbox because the kernel returns `Operation not permitted`; this is not claimed as live raw validation. Non-loopback IPv6 neighbor resolution, raw SYN/UDP/OS injection, and privileged ICMP/ICMPv6/NDP exchange remain capability-dependent and are reported explicitly.


## Phase 22 Audit Record

Phase 22 adds deterministic target-aware raw-interface selection, allowing omitted Linux interfaces to be derived from operational source and route evidence while preserving explicit user selection. Mixed-family targets must be satisfiable by one operational interface. Loopback selection is permitted for controlled local tests even when the kernel does not expose a conventional route entry for `lo`.

The Linux ARP path now uses the selected interface MAC and source IPv4 address, and validates Ethernet and ARP identities before accepting replies. TCP Connect preserves routed-unreachable and local-source-address failures as explicit states and reasons. Raw UDP records target preflight and injection diagnostics in the shared session. Raw OS capability failures now terminate the live stage with a structured nonzero error rather than returning success with an unavailable identity.

Unit, integration, offline, and controlled-loopback checks passed for the changed paths. The sandbox still denies AF_PACKET with `Operation not permitted`, so raw SYN, ARP, NDP, raw UDP, ICMP/ICMPv6, and raw OS exchange remain capability-dependent and are not claimed as live-validated. No public target traffic was used. The remaining gap is privileged private-lab execution, not a hidden fallback or fabricated result.


## Phase 23 Audit Record

Phase 23 confirms that the Phase 22 baseline contains no artificial authorization gate, mandatory loopback policy, private-range allowlist, hidden target fallback, or public-target automation. User-supplied syntactically valid IPv4/IPv6 targets continue through the existing target expansion, resource bounds, interface capability checks, and explicit transport selection.

The implementation adds typed discovery `UNREACHABLE` evidence, exact quoted IPv4/IPv6 ICMP unreachable correlation for TCP SYN and discovery probes, canonical host-unreachable summary fields, and strict `-p`/`-p-` TCP selection compatibility. The existing single epoll reactor, timers, schedulers, packet parsers, correlation tables, bounded service/TLS identification, OS matcher, metrics, and output model remain the only production execution path.

Validation is restricted to offline, loopback, controlled-local, and documentation-address fixtures. The complete regression suite passes. AF_PACKET-dependent tests remain capability-gated and report the exact sandbox diagnostic `Operation not permitted`; no live raw exchange is claimed. No public target was contacted, and no threads, polling/sleep loops, shell execution, credentials, persistence, evasion, spoofing, exploitation, copied Nmap code, or copied Nmap data were introduced.


## Phase 24 Audit Record — Production Live Validation & Capability Completion

The Phase 23 baseline was audited before modification. It is synchronized with `origin/main`, preserves one epoll-based IOEngine and the established pipeline, and contains no `AuthorizationGate`, mandatory loopback restriction, private-range allowlist, hidden authorization mechanism, prohibited production thread/poll/sleep/system API, duplicate reactor, or duplicate pipeline.

Phase 24 closes a transmit-integrity gap in the existing Linux TCP SYN adapter: final TCP checksums are now calculated against the selected IPv4 or IPv6 pseudo-header addresses during frame composition. Existing Phase 23 typed unreachable evidence, quoted packet correlation, deterministic source/interface selection, bounded scheduling, service/TLS identification, OS matching, metrics, cancellation, shutdown, and canonical output remain in place.

| Area | Phase 24 evidence and status |
| --- | --- |
| IPv4 Connect | Loopback open/closed validation passed through real nonblocking sockets; unit tests cover timeout, unreachable, local-source, and cancellation semantics. |
| IPv6 Connect | Existing local `::1` integration path is exercised when the host IPv6 stack provides it; no external IPv6 target was used. |
| Raw SYN/UDP/discovery/ARP/NDP/ICMP/OS | Implemented and capability-gated; sandbox AF_PACKET access returns `Operation not permitted`, so no raw live success is claimed. |
| Service/TLS | Existing bounded project-owned probes and identification-only TLS parsing remain active; no authentication, certificate exploitation, MITM, or credential collection was added. |
| Source/interface selection | Deterministic target-family, route/source, operational-state, capability, and explicit-interface rules remain active. |
| Timing/lifecycle | Existing one-shot timers, adaptive timing, bounded concurrency, cancellation, descriptor teardown, correlation cleanup, and canonical partial-report behavior remain active and regression-tested. |
| Security | Packet bounds, strict parsing, checksum validation, exact correlation, duplicate/late isolation, bounded service input, and escaped output remain enforced. |

All validation was restricted to offline, loopback, controlled-local, or documentation-address fixtures. No arbitrary public target was contacted. The remaining raw validation requirement is environmental and requires an explicitly authorized private lab with AF_PACKET permission and suitable IPv4/IPv6 topology.


## Phase 25 Audit Record — Production Live Remote Network Scanning

The Phase 24 baseline was audited before changes. It was clean and synchronized at `816c1796b02e2dd06cc64bc5e23540dde85ae00e`, retained one `IOEngine` epoll reactor and the established staged pipeline, and contained no artificial authorization layer, mandatory loopback policy, private-range allowlist, hidden fallback, prohibited thread/poll/sleep/system APIs, or duplicate scanner architecture.

Phase 25 adds explicit `--transport connect` CLI compatibility and updates usage text so Connect, offline, and Linux raw modes are named distinctly. The Linux SYN frame path retains deterministic source-port/sequence identity, strict correlation, selected source/interface handling, ARP/NDP prerequisites, and final IPv4/IPv6 TCP pseudo-header checksum construction. The change does not move work out of the existing reactor or schedulers.

| Capability | Status in this environment |
| --- | --- |
| IPv4/IPv6 literals, CIDR, ranges, hostnames, mixed targets | Implemented through the existing bounded Target Engine. |
| Explicit Connect transport | Implemented; local IPv4 and IPv6 Connect scans exercised successfully. |
| Offline transport | Implemented and regression-tested through existing injected/recording fixtures. |
| Linux raw SYN/UDP | Implemented and capability-gated; AF_PACKET unavailable with `Operation not permitted`. |
| ICMP/ICMPv6, ARP, NDP discovery | Existing strict typed paths remain implemented; raw live exchange not exercised in this sandbox. |
| Service and TLS detection | Existing bounded project-owned probes and identification-only TLS handling remain active; raw remote validation requires a privileged lab. |
| OS detection | Existing family-safe project-owned matcher and raw adapter remain active; raw evidence path was not live-exercised here. |
| Output and diagnostics | Canonical normal/JSON/XML/grepable output and stderr diagnostics remain deterministic and capability-honest. |

No public or arbitrary external target was contacted. The remaining remote validation work requires explicitly authorized operator-owned IPv4/IPv6 infrastructure, suitable routes and neighbors, and AF_PACKET capture/injection permission. No raw live success is claimed without that environment.


## Phase 26 Audit Record — Privileged Real-Network Validation & Hardening

### Environment

| Field | Observed evidence |
| --- | --- |
| Kernel | `Linux 305f57cac429 6.1.102 #1 SMP PREEMPT_DYNAMIC Apr 20 12:34:49 UTC 2026 x86_64` |
| Privileges | `uid=1000(ubuntu) gid=1000(ubuntu)` with membership in `sudo`, but no privileged raw capability available to the running process. |
| Interfaces | `lo` is up with `127.0.0.1/8` and `::1/128`; `eth0` is up with `02:fc:00:00:00:05`, IPv4 `169.254.0.21/30`, and IPv6 link-local `fe80::fc:ff:fe00:5/64`. |
| IPv4 route | Default via `169.254.0.22` on `eth0`; directly connected `169.254.0.20/30` route. |
| IPv6 route | Link-local `fe80::/64` on `eth0`; loopback `::1/128` on `lo`. |
| Neighbor | `169.254.0.22` on `eth0` with MAC `be:80:97:07:c9:b1`, state `REACHABLE`. |
| AF_PACKET | Capture open failed with exact `Operation not permitted`. |
| Toolchain | GNU Make 4.3, g++ 13.3.0, no `clang++`. |

### Implementation and diagnostics

Phase 26 adds one shared raw-stage diagnostic formatter. Representative failure output is:

`transport=linux interface=eth0 family=ipv4 operation=af_packet_capture category=CAPTURE_UNAVAILABLE errno=1 message=Operation not permitted`

The failure remains terminal and is emitted on stderr. No raw failure is converted into a fabricated scan result, Connect result, offline result, or success state.

### Controlled validation

| Test | Target/interface | Observed result | Evidence |
| --- | --- | --- | --- |
| IPv4 TCP Connect | `127.0.0.1`, Connect | Validated; normal report and closed-port classification produced. | Existing local socket integration and CLI smoke. |
| IPv6 TCP Connect | `::1`, Connect | Validated; JSON output parsed structurally. | Existing local socket integration and CLI smoke. |
| Raw IPv4 SYN | `127.0.0.1`, `lo` and `eth0` | Not validated; terminal capability failure. | `CAPTURE_UNAVAILABLE`, errno 1, `Operation not permitted`. |
| Raw IPv6/SYN, NDP, ICMPv6 | `::1`/link-local candidates | Not validated; AF_PACKET unavailable. | No packet evidence claimed. |
| UDP/raw discovery/ARP | Controlled local invocation only | Not validated live; existing offline/injected and capability-gated tests remain available. | No public target or uncontrolled server contacted. |
| Output and parser matrix | Loopback and bounded target specifications | Version/help, interface JSON, IPv4/IPv6 resolution, mixed targets, JSON parsing, and failure semantics passed. | CLI smoke logs and regression suite. |

### Security and stability

The production source audit found no prohibited thread, polling, sleeping, shell execution, duplicate-reactor, duplicate-scheduler, or hidden-fallback implementation. The clean build, complete tests, debug, release, ASan/LSan, UBSan, coverage, and fuzz capability checks passed. `clang++` is absent, so libFuzzer execution is recorded as skipped; no fuzz execution is claimed. Raw tests retain the exact capability skip diagnostic.

### Limitations

No packet-capture evidence for SYN/SYN-ACK, SYN/RST, ARP, NDP, UDP response, or ICMP unreachable is recorded because the sandbox cannot open AF_PACKET. A privileged, explicitly authorized operator-owned private IPv4/IPv6 lab is required for genuine raw live validation. No public or arbitrary external target was contacted.
