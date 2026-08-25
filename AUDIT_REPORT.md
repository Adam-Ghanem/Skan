# Skan Phase 0–11 Engineering Audit

## Scope and conclusion

This audit reviewed the Phase 0–11 implementation, including the core model, single-reactor I/O path, packet parsers, discovery and port schedulers, service and OS detection, adaptive timing, Linux transport/capture, output, CLI, orchestration, tests, documentation, and Makefile. The implementation remains a **Nmap-inspired, Linux-first network-scanning engine** rather than an Nmap-compatible replacement. The audit found several concrete lifecycle and scalability defects and repaired them without introducing a new reactor, worker threads, a target-range subsystem, a new protocol family, or a second result/output model.

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

The explicit target boundary is intentionally incomplete for professional hostname, CIDR, range, normalization, mixed-target, and large-scale deduplication support. This is documented as the next major subsystem rather than being hidden inside Phase 11. Live raw-packet OS fingerprinting also remains capability-gated and unavailable in this build; injected evidence collection and deterministic matching remain implemented.

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
| Live raw OS fingerprinting | Unavailable/capability-honest; injected architecture implemented |
| UDP scanning | Not added by this audit |
| Evasion, spoofing, exploitation, credential handling, persistence | Out of scope |

## G. Testing upgrade

The complete Makefile test graph contains 70 test-binary executions. New and strengthened coverage includes stale epoll batch records, PacketReceiver attach/detach and close lifecycle, oversized capture frames, unknown TCP options, closed-reactor timer failure, queued-cancellation metric arithmetic, 10,000 timers, 10,000 correlations, 1,000-host × 100-port orchestration, pipeline cancellation, discovery response handling, service/OS ordering, and capability-aware Linux skips.

An optional offline libFuzzer target exercises Ethernet, IPv4, TCP, UDP, ICMP, service-database, OS-database, port-selection, and timing-profile parsers. If Clang and its fuzzer runtime are unavailable, `make fuzz` reports `SKIPPED` and exits successfully; it never fabricates a fuzz result.

## H. Documentation and build findings

`README.md` and `ARCHITECTURE.md` now distinguish implemented, capability-gated, offline/injected, and planned behavior. They document the one-reactor model, explicit transport selection, partial-report cancellation, output boundary, target-engine gap, stress coverage, and fuzz behavior. The Makefile now exposes `release`, `debug`, `asan`, `ubsan`, `coverage`, and optional `fuzz` targets while retaining C++20/C11 and the existing strict warning set.

## I. Validation record

The following gates passed after the final changes:

| Gate | Result |
| --- | --- |
| Clean production build | Passed |
| Complete release test suite | Passed; 70 binaries executed |
| Debug build | Passed |
| AddressSanitizer with leak detection | Passed |
| UndefinedBehaviorSanitizer | Passed |
| Coverage target | Passed |
| Release target | Passed |
| Optional fuzz target | Clean `SKIPPED`; Clang unavailable in the environment |
| CLI version/help and offline output matrix | Passed |
| Linux capability failure behavior | Passed; explicit failure, no fallback |
| `git diff --check` | Passed before commit |

AF_PACKET-dependent tests were skipped because the execution environment returned `Operation not permitted`. No raw-network test was marked as a successful live test under that limitation.

## J. Recommended upgrade order

The next target-related upgrade should replace the current synchronous platform resolver with an asynchronous implementation behind the existing injectable `HostnameResolver` boundary if hostname resolution latency becomes material. The existing parser, CIDR/range expansion, canonicalization, deduplication, explicit limits, and numeric ordering should remain unchanged.

Live OS fingerprinting can be implemented only through an explicit capability-gated transport that reuses the existing OS probe, correlation, scheduler, matcher, and report boundaries. Broader protocol coverage, larger corpus management, and optional scripting should follow only after their ownership and resource limits are specified. Performance work should continue with measured benchmarks for target expansion, packet parsing, correlation, queue operations, matching, and output serialization rather than speculative rewrites.

## References

[1]: include/io/io_engine.hpp "IOEngine public ownership and lifecycle contract"
[2]: src/io/io_engine.cpp "Tokenized epoll dispatch and timer implementation"
[3]: src/orchestrator/scan_pipeline.cpp "Unified Phase 11 pipeline"
[4]: src/orchestrator/scan_report_builder.cpp "Canonical report mapping and host indexing"
[5]: Makefile "Build, test, sanitizer, coverage, and fuzz targets"
