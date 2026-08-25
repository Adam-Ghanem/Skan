# Post-Phase-15 Deep Audit of Skan

**Author:** Manus AI
**Audit date:** 25 August 2026
**Repository:** `/home/ubuntu/skan`
**Revision audited:** `d9f63df` — `Implement Phase 15 IPv6 dual-stack scanning foundation`
**Audit status:** Historical Phase 15 baseline; Phase 16 reconciliation appended below
**Implementation status:** The original audit made no implementation changes. Phase 16 changes and their verification are recorded in the addendum below.

## 1. Executive conclusion

Skan at revision `d9f63df` is a coherent, capability-honest, Linux-first scanning engine with a deliberately narrower scope than Nmap. The strongest architectural property is preserved: one thread-affine `io::IOEngine` epoll reactor and one timer mechanism are reused by discovery, TCP/UDP schedulers, service detection, OS detection, packet capture, and orchestration. The Phase 15 implementation adds a typed binary IPv4/IPv6 identity, bounded IPv6 packet primitives, family-aware observation and correlation, AF_INET6 Connect, offline dual-stack construction, and family-aware output without introducing a second reactor, packet stack, scheduler, thread, polling loop, implicit interface selection, or live-network fallback.

The implementation is **production-grade within its declared boundary**, but the boundary is materially narrower than Nmap’s. IPv6 target parsing, canonicalization, bounded CIDR/range handling, synchronous A+AAAA resolution, offline packet construction, PacketReceiver parsing, injected discovery/UDP behavior, Connect scanning, TCP service transport, and output serialization are present. Native Linux raw IPv6 capture/injection, complete IPv6 Neighbor Discovery, IPv6 OS fingerprinting, UDP service inference, reverse DNS, broad service/OS corpora, NSE, SCTP/IP-protocol scans, traceroute, and advanced Nmap scan techniques remain unavailable or intentionally out of scope.

The audit found no evidence of an architectural violation or an immediate memory-safety failure in the tested paths. It did identify several **important remaining gaps**: TCP/UDP receive checksum validation is not symmetric with ICMPv6 validation; the CLI accepts very large user-supplied resource limits without a hard upper ceiling; fuzzing is only build-skipped because Clang is unavailable and does not constitute runtime fuzz evidence; the benchmark is offline and IPv4-shaped; live IPv6 raw and IPv6 service integration remain unproven in this environment; and the compact service/OS datasets cannot support Nmap-like identification breadth. These findings should shape Phase 16 rather than be hidden behind generic “IPv6 supported” wording.

## 2. Scope and audit method

This audit examined the committed source, headers, Makefile, tests, benchmark harness, data files, CLI behavior, capability reporting, and current documentation. The inspection used the repository as the source of truth and treated prose claims as hypotheses to verify against source and executable behavior. It also consulted the official Nmap Reference Guide for the comparison sections; Nmap was not used to generate traffic and no public target was contacted.

The audit covered the following dimensions:

| Dimension | Evidence examined | Result |
| --- | --- | --- |
| Revision and cleanliness | `git log`, `git status`, `git rev-parse` | Audited revision is `d9f63df`; baseline was clean and synchronized before the audit artifact was written. |
| Build graph | `Makefile`, compiler/link rules | All Phase 15 packet sources and tests are registered in the existing graph; 77 test binaries are registered. |
| Runtime validation | `make`, `make test`, `debug`, `release`, `asan`, `ubsan`, `coverage`, `fuzz`, CLI matrix | Normal, debug, release, ASan, UBSan, and coverage gates passed. AF_PACKET tests skipped honestly due `Operation not permitted`; fuzz target skipped honestly because `clang++` is unavailable. |
| Architecture | `include/io`, `include/packet`, `include/net`, schedulers, orchestrator | One IOEngine/reactor and one timer path remain; transports and stages reuse shared boundaries. |
| Security and robustness | bounds checks, allocations, raw memory operations, parser paths, capability gates | No critical tested parser failure found; several medium-risk hardening opportunities remain. |
| Performance | `benchmarks/offline_benchmark.cpp`, generated CSV | Tested workloads scale approximately linearly, but measurements are offline and IPv4-shaped. |
| External comparison | Official Nmap guide pages | Skan is narrower and safer by design, not an Nmap-compatible replacement. |

## 3. Repository and architecture inventory

The project is organized around a layered dependency direction. `core` provides status, logging, constants, shared typed addresses, hosts, targets, and port values. `io` provides the single epoll reactor, borrowed event registrations, and monotonic timers. `packet` provides the wire model and serialization/parsing boundary. `target` parses and normalizes user target specifications before the reactor begins. Discovery, port scanning, service detection, and OS detection own bounded logical work and use injected or transport interfaces. Linux adapters own descriptor and byte movement. The orchestrator owns stage sequencing, cancellation, aggregation, and output handoff.

The public IO contract in `include/io/io_engine.hpp:18-65` explicitly documents a single-thread-affine epoll reactor, caller-owned events, bounded `run_once`, clean `stop`, shutdown detachment, and monotonic one-shot timers. `include/io/event.hpp:35-67` documents the event lifetime contract and prohibits copying or moving registered event objects. `include/orchestrator/scan_session.hpp:50-94` shows that each scan session owns one `IOEngine` and exposes the same engine to all stages.

The packet model remains the source of truth. `include/packet/packet.hpp:22-59` holds one shared composer with Ethernet, IPv4 or IPv6, TCP/UDP, and ICMPv4/ICMPv6 elements. `include/packet/ipv6_extensions.hpp:11-48` defines one bounded extension parser for Hop-by-Hop, Routing, Fragment, and Destination Options. `include/net/packet_receiver.hpp:23-107` carries typed IPv4/IPv6 observations and extension metadata in the existing receiver contract rather than creating a second capture parser.

The typed identity boundary is appropriate. `include/core/types.hpp:12-38` defines `AddressFamily`, a 16-byte binary `IpAddress`, deterministic ordering, hashing, and canonical conversion. `core::Host` appends `ip_address` at `include/core/types.hpp:58-63`, retaining compatibility with earlier aggregate initialization. `include/net/packet_filter.hpp` and the corresponding implementation use the typed address in correlation identity, preventing IPv4 and IPv6 observations from matching solely because their textual or numeric portions resemble one another.

Target resolution is intentionally performed before the scan reactor. `src/target/target_engine.cpp:252-305` uses synchronous `getaddrinfo` with `AF_UNSPEC` and deduplicates A/AAAA results by binary identity. `src/target/target_engine.cpp:436-573` bounds expansion and rejects IPv6 CIDRs with 64 or more host bits before attempting enormous expansion. IPv6 ranges are limited to a shared upper 64-bit prefix and checked for a bounded count. The public comment in `include/target/target_engine.hpp:135-143` still says “AF_INET” even though the implementation uses `AF_UNSPEC`; this is a documentation defect, not a behavior defect.

The orchestrator remains sequential at the stage level. `ScanSession` owns state, counters, cancellation, error text, report, and timestamps. Stage dependencies are injected through `include/orchestrator/scan_stage.hpp`, with each stage receiving the same session reactor. This is a good fit for deterministic injected tests and makes capability failures observable, although it is less feature-rich than Nmap’s group-oriented and script-oriented execution model.

## 4. Phase 0–15 verification

The phase table below combines the phase-labeled Git history with source and test verification. “Complete” means implemented and represented in the current build; it does not mean feature parity with Nmap.

| Phase | Milestone verified from history | Current source-backed status | Audit conclusion |
| --- | --- | --- | --- |
| 0 | Project foundation; C++20 upgrade | Core status, constants, logging, shared types, strict GNU Make build | Complete for foundation scope. |
| 1 | Asynchronous IO engine and audit strengthening | Epoll `IOEngine`, event registration, timer queue, shutdown, tokenized callback validation | Complete; lifecycle is one of the strongest parts of the codebase. |
| 2 | Packet layer | Ethernet, IPv4, TCP, UDP, ICMPv4 plus shared checksum and packet composition | Complete for implemented protocols. |
| 3 | Host discovery | Discovery contracts, ICMP/TCP/ARP probes, scheduler, injected transport, Linux capability gate | Complete for declared subset; no UDP/SCTP/IP-protocol discovery parity. |
| 4 | Scoped TCP port scanning | Connect and SYN probe contracts, scheduler, states/reasons, timers, correlation | Complete for Connect and explicit Linux SYN scope. |
| 5 | Service detection | Bounded project-owned TCP probes, matcher, scheduler, Connect transport | Complete as a compact inventory detector; not broad version-detection parity. |
| 6 | Capability-honest OS fingerprinting architecture | Typed OS evidence, matcher, scheduler, injected transport, explicit unavailable result types | Complete as architecture and offline/injected scope. |
| 7 | Adaptive timing scan engine | Timing profiles, RTT estimator, congestion/backoff, bounded adaptive scheduler | Complete for current controls; fewer knobs than Nmap. |
| 8 | Deterministic output serialization | Normal, JSON, XML, grepable writers and canonical report model | Complete for Skan’s schema; not Nmap XML/DTD compatibility. |
| 9 | Network transport and capture | Linux transport/capture, PacketReceiver, filters, correlation, explicit interfaces | Complete where AF_PACKET permission exists; tests skip when unavailable. |
| 10 | Real network integration | Linux discovery, SYN, UDP, OS adapters and controlled capability tests | Complete for IPv4 raw scope; environment does not provide live AF_PACKET acceptance. |
| 11 | Unified scan orchestrator plus hardening | Session, sequential stages, cancellation, report builder, output handoff | Complete; no duplicate reactor or output model found. |
| 12 | Target engine | IPv4/IPv6 literals, CIDR/ranges, mixed input, bounded resolver, dedup/order | Complete within explicit limits; synchronous DNS is a known latency boundary. |
| 13 | UDP scan engine | Shared UDP scheduler, bounded probe DB, retries, timeout/classification, raw IPv4 adapter | Complete for declared subset; no UDP service inference. |
| 14 | Live OS fingerprinting engine | IPv4 raw/injected OS probe families, DB loader, matcher, structured unavailable state | Complete for IPv4 capability-gated scope; IPv6 is intentionally unavailable. |
| 15 | IPv6 dual-stack foundation | Typed family identity, IPv6 packet/extensions/checksums/ICMPv6, family-aware receiver/correlation, AF_INET6 Connect/service, offline dual-stack paths, output/CLI/tests | Complete within declared boundary; native Linux raw IPv6, complete ND, and IPv6 OS detection are explicitly not claimed. |

## 5. Capability matrix

| Capability | Status at `d9f63df` | Evidence and interpretation |
| --- | --- | --- |
| IPv4 literal/CIDR/range targets | Implemented | Target parser and bounded expansion. |
| IPv6 literal/CIDR/range targets | Implemented within limits | Canonical binary identity and bounded host-bit expansion. `/64` and larger expansions are rejected rather than materialized. |
| Mixed IPv4/IPv6 targets | Implemented | `resolve 127.0.0.1,::1 --json` returned deterministic family fields. |
| A+AAAA hostname resolution | Implemented, synchronous | `getaddrinfo(AF_UNSPEC)` runs before reactor entry; no background resolver exists. |
| IPv6 zone IDs | Not supported | `parse_ipv6_text` rejects `%`; this differs from Nmap’s documented link-local zone-ID syntax. |
| IPv6 base header | Implemented | Strict fixed 40-byte model, version and payload bounds. |
| IPv6 extensions | Bounded recognition only | Four extension kinds recognized; unsupported/malformed/limit states are explicit. No full extension ecosystem or fragment reassembly. |
| TCP/UDP/ICMPv6 checksum construction | Implemented | Shared IPv6 pseudo-header helper and serializer paths. |
| IPv6 receive checksum validation | Partial | ICMPv6 is validated in PacketReceiver; TCP/UDP receive paths do not validate pseudo-header checksums. |
| ICMPv6 Echo/errors/limited ND | Implemented within scope | Typed parser/serializer and limited recognition. No complete ND state machine. |
| IPv6 PacketReceiver | Implemented | EtherType `0x86DD`, bounded payload/extension parsing, typed observations. |
| Family-aware filtering/correlation | Implemented | Binary family and address identity are included in keys. |
| AF_INET6 TCP Connect | Implemented | Existing nonblocking IOEngine lifecycle; controlled `::1` loopback test. |
| AF_INET6 service Connect | Implemented in code | Same stream lifecycle; current live service fixture remains IPv4-only. |
| Offline IPv6 discovery/UDP | Implemented | Existing scheduler and recording seams are reused. |
| Native Linux raw IPv6 | Explicitly unavailable | No implicit interface selection, fallback, or fabricated success. |
| IPv6 OS fingerprinting | Explicitly unavailable | Structured `UNAVAILABLE`, zero confidence, no address-derived identity. |
| UDP service/OS inference | Not implemented | Silence remains `OPEN_OR_FILTERED`; no fabricated service or OS evidence. |
| Reverse DNS | Not implemented in current CLI surface | Nmap has configurable reverse-DNS phases; this is a product-scope gap. |
| NSE/scripting | Not implemented and prohibited by current scope | Requires a separate sandbox, authorization, resource, and output design. |
| SCTP, IP protocol, traceroute, advanced scan methods | Not implemented | Deliberately outside current safe subset. |

## 6. Security and correctness findings register

The findings below are ranked by practical impact within the current product boundary. “Open” means the finding is a recommended Phase 16 item or an explicit acceptance limitation; it does not imply that the current implementation is unsafe for its declared controlled scope.

| ID | Severity | Finding | Evidence | Impact | Recommendation |
| --- | --- | --- | --- | --- | --- |
| F-01 | High | IPv6 TCP/UDP receive checksums are not validated in `PacketReceiver`, while ICMPv6 checksums are validated. | `src/net/packet_receiver.cpp:132-180`; only ICMPv6 calls `ipv6_pseudo_header`. | A syntactically valid but checksum-invalid TCP/UDP packet can enter observation/correlation paths. This weakens integrity and can produce false positives if a transport adapter correlates fields without independently validating the checksum. | Add shared pseudo-header verification for TCP/UDP observations, with explicit handling for UDP checksum zero as invalid in IPv6. Add positive, bad-checksum, odd-length, and extension-chain tests for both families. |
| F-02 | Medium | CLI and public APIs accept arbitrarily large numeric target limits; the hostname resolver calls `seen.reserve(max_results)`. | `src/main.cpp:109-117, 284-293, 531-540, 719-728`; `src/target/target_engine.cpp:265-271`. | A user can request a very large reservation and cause avoidable memory pressure or process termination before the normal `max_targets` expansion bound is reached. This is primarily a local denial-of-service against the scanner process. | Introduce hard maximums for `max_targets` and `max_hostname_results`, validate them at the CLI boundary and in `TargetLimits`, and reserve only a bounded amount. |
| F-03 | Medium | The offline fuzz harness is broad, but no fuzz runtime result was obtained in this environment. | `tests/fuzz/fuzz_packet_parsers.cpp:23-73`; `make fuzz` reported `SKIPPED: clang++ is unavailable`. | Parser robustness is supported by deterministic tests and sanitizers, but coverage-guided fuzzing has not been executed here. | Run libFuzzer in CI with a pinned Clang toolchain, seed corpus, duration/coverage budget, and artifact retention. Add CLI parser, output, full scheduler, and orchestrator harnesses only with explicit bounds. |
| F-04 | Medium | Coverage target is an instrumentation/test gate, not a coverage-threshold gate. | `Makefile:582-610`; `make coverage` completes the instrumented test path but no percentage threshold or report artifact is enforced. | “Coverage passed” does not prove that critical branches such as unsupported IPv6 extensions, capability failures, and output errors have a measured minimum coverage. | Generate an explicit coverage report and enforce thresholds for packet parsing, target limits, capability state transitions, and output serialization. |
| F-05 | Medium | Current benchmark evidence is offline and IPv4-shaped. | `benchmarks/offline_benchmark.cpp:28-74, 115-258`; generated CSV contains documentation-space IPv4 targets. | The measured linear growth and RSS are useful regression baselines but do not prove dual-stack, DNS, IPv6 packet, live capture, Connect, or service behavior at scale. | Add controlled IPv6 and mixed-family offline benchmark rows, then separately add private-lab live benchmarks with fixed interface, privilege, topology, and timing parameters. |
| F-06 | Medium | Live IPv6 service-detection integration coverage is absent. | `tests/integration/detect/test_service_detection_local.cpp:17-46, 72-118` creates AF_INET listeners and `127.0.0.1` results only. | AF_INET6 service transport compiles and is exercised indirectly, but the service lifecycle and banner matching over `::1` are not directly verified. | Add a conditional `AF_INET6` loopback listener and SSH/HTTP-like responders using the same service detector and scheduler. |
| F-07 | Medium | IPv6 zone identifiers are rejected. | `src/target/target_engine.cpp:34-47` rejects any `%` in an IPv6 literal. | Link-local targets such as `fe80::1%eth0` cannot be represented. This is a functional gap for scoped local IPv6, although rejecting ambiguous scope is safer than silently selecting an interface. | Add an explicit scoped-address type containing binary address plus validated interface/index, and require an explicit interface for all link-local live behavior. Do not accept or strip a zone ID implicitly. |
| F-08 | Low | The public TargetResolver comment is stale and says the default resolver calls `getaddrinfo(AF_INET)`. | `include/target/target_engine.hpp:135-143` versus `src/target/target_engine.cpp:254-256`. | Documentation can mislead maintainers about A+AAAA behavior. | Correct the comment in the next documentation-only change. |
| F-09 | Low | `parse_ipv6_extensions` is declared `noexcept` while appending to a vector. | `include/packet/ipv6_extensions.hpp:44-48`; `src/packet/ipv6_extensions.cpp:84`. | The header-count limit makes ordinary allocation small, but a `bad_alloc` under memory pressure would terminate rather than return a typed resource failure. | Either use fixed-capacity storage for the maximum eight headers or remove `noexcept` and translate allocation failure at a higher boundary. |
| F-10 | Low | Output is structured and deterministic but not Nmap-compatible. | `include/output/result_model.hpp:42-85`; writers under `src/output`. | Consumers expecting Nmap XML DTD elements, host addresses, ports, runstats, and resume semantics cannot consume Skan output as a drop-in replacement. | Treat the existing schemas as Skan contracts. If interoperability is required, add a separately versioned export adapter and schema tests rather than mutating the canonical model. |

F-01 and F-02 are the most actionable correctness/security findings. F-03 through F-06 are validation and acceptance gaps. F-07 through F-10 are explicit scope or hardening items rather than evidence of a current architectural failure.

## 7. Lifecycle, resource, and concurrency audit

The one-reactor constraint is satisfied. A production-source search found no `std::thread`, `pthread`, `std::async`, `poll`, `select`, or sleep-based loop outside prohibited or documentation contexts. The current event model is intentionally thread-affine. Events are borrowed by `IOEngine`, registration tokens are used to revalidate epoll records, and shutdown detaches registrations without destroying caller-owned events. This is consistent with the ownership comments in `include/io/io_engine.hpp` and `include/io/event.hpp`.

Timers use `std::chrono::steady_clock` and a priority queue. Schedulers retain logical pending entries and handle timer ID zero or cancellation failures as terminal outcomes rather than silently leaving work pending. Existing Phase 14 hardening addressed stale epoll records, timer allocation failure, correlation cleanup, aggregate output writes, and borrowed database lifetime. The current audit did not find a new lifecycle violation in the Phase 15 additions.

The principal resource concern is **user-configurable limit magnitude**, not unbounded protocol parsing. Target expansion reserves at most `min(max_targets, 1024)` in its main vectors, IPv6 extension parsing is bounded to eight headers and 2,048 bytes, PacketReceiver clamps retained frame input to 65,535 bytes, and service responses are bounded by `max_response_bytes`. The hostname resolver’s direct `reserve(max_results)` is the exception and should receive a hard upper ceiling.

The single-thread model simplifies data races, but it means all synchronous hostname resolution and all callback work execute on the caller’s thread. This is acceptable for current pre-reactor resolution and deterministic tests. It becomes a responsiveness risk when DNS latency, very large target lists, or future richer database loading are introduced. Any asynchronous resolver should be built behind the existing `HostnameResolver` seam and must not create a second reactor or background thread without a separately reviewed architecture.

## 8. Target-engine audit

The target parser correctly distinguishes IPv4, IPv6, CIDR, ranges, and hostnames. Binary identity is used for deduplication and ordering, and canonical rendering is supplied through `inet_ntop`. Hostname resolution uses `AF_UNSPEC` and accepts both A and AAAA results. The implementation rejects IPv6 zone IDs, which avoids unsafe implicit scope handling but prevents link-local targets.

IPv6 expansion is deliberately conservative. A CIDR with at least 64 host bits is rejected as resource-exhausted before shifting or materializing a huge range. IPv6 ranges are accepted only when the first eight bytes match, so the low 64-bit count can be computed safely. Expansion also checks the global `max_targets` bound while appending. This is safer than accepting Nmap-like `/0` syntax and attempting to enumerate it, but it is a product difference that should remain prominent in help text.

The remaining target issue is the absence of a hard maximum for user-supplied limits. `std::from_chars` validates unsigned syntax, but the resulting `size_t` can still be very large. A future fix should distinguish a user-facing requested limit from an internal reservation size and impose a documented hard ceiling.

## 9. Packet and capture audit

The IPv6 base header model is strict: `IPv6::parse` requires at least 40 bytes, checks version 6, reads traffic class, flow label, payload length, next-header, hop-limit, and 128-bit addresses, then rejects a declared payload longer than the supplied input. Serialization validates version and flow-label width and requires a 40-byte output span.

The extension parser recognizes Hop-by-Hop, Routing, Fragment, and Destination Options. It uses explicit maximum header and byte budgets and returns `Complete`, `NoNextHeader`, `Unsupported`, `Malformed`, or `LimitExceeded`. Fragment metadata is exposed, but the implementation does not reassemble fragments and does not claim to support fragmented transport scanning. Unsupported terminal protocols are surfaced rather than guessed.

PacketReceiver validates Ethernet bounds, IPv6 base-header bounds, declared IPv6 payload bounds, extension outcomes, TCP minimum length, UDP declared length, and ICMPv6 minimum length/checksum. The IPv4 path retains its hardened declared-UDP-length slicing. The material remaining issue is transport checksum symmetry: ICMPv6 receives pseudo-header verification, but TCP and UDP observations are only structurally parsed. Since the packet serializer already has the shared checksum helper, receive verification is a contained Phase 16 improvement.

The current packet layer intentionally does not provide VLAN/QinQ decoding, AH/ESP/Mobility extension support, full fragment reassembly, or advanced extension normalization. These should not be added casually because each changes correlation, capture, and resource-limit semantics.

## 10. Discovery, scanning, service, and OS boundaries

Discovery reuses one scheduler and one probe submission contract. IPv6 ICMP Echo and TCP probe construction are available offline/injected, while ARP remains IPv4-only. The CLI’s offline `discover ::1` execution returned a clear unknown/timeout outcome rather than pretending that offline mode had reached the loopback host.

TCP Connect is the most complete end-to-end IPv6 path. The same nonblocking socket event lifecycle constructs `AF_INET6` sockets and submits `sockaddr_in6` addresses. A controlled mixed scan of `127.0.0.1,::1` against port 1 produced deterministic `CLOSED`/`CONNECTION_REFUSED` results for both families. This verifies the core dual-stack Connect path without public traffic.

Service detection uses the existing stream transport and bounded probe database, and it accepts typed IPv6 targets. However, the real local service fixture is still AF_INET-only. This is a test coverage gap, not proof that the transport is broken. The service database is intentionally compact: HTTP, SSH, FTP, SMTP, TLS greeting, and a generic fallback. It is not comparable in breadth to Nmap’s corpus.

OS detection is capability-honest. IPv6-containing targets are rejected at the OS stage with structured `UNAVAILABLE` and zero confidence; no OS identity is inferred from address, port, service, or local platform. The live IPv4 path remains explicitly interface- and AF_PACKET-dependent. The project-owned OS corpus contains three laboratory-style generic fingerprints, so even the IPv4 path should be described as bounded evidence matching rather than broad operating-system identification.

UDP uses the existing scheduler, retries, timeout semantics, typed identity, and recording transport. Silence remains `OPEN_OR_FILTERED`, and no UDP service/OS inference is fabricated. IPv6 raw UDP is unavailable in the Linux adapter, which is preferable to silently choosing Connect or offline mode.

## 11. Output and CLI audit

The canonical `HostResult` carries `family` alongside address, state, ports, services, OS results, warnings, and errors. JSON, XML, normal, and grepable outputs visibly distinguish IPv4 and IPv6. A mixed scan produced stable JSON host objects with `family: "ipv4"` and `family: "ipv6"`; XML emitted `family="ipv4"`/`family="ipv6"`; grepable output retained a one-line key-value record with `family=...`.

The output contract is internally coherent but intentionally not Nmap-compatible. Nmap’s XML is designed around a published DTD and includes richer host/status/address/port/runstats structures; Skan’s XML is a smaller Skan-specific schema. This is acceptable provided documentation continues to call it XML output rather than Nmap XML compatibility.

The CLI matrix passed for help, version, mixed resolve, IPv6 CIDR resolve, offline IPv6 discovery, mixed Connect scan in JSON/XML/grepable forms, UDP offline, service detection, IPv6 OS-unavailable output, timing controls, interface inspection, invalid target syntax, explicit Linux transport without an interface, and an invalid implicit SYN transport request. The invalid Linux and transport cases failed clearly and did not fall back.

One usability mismatch remains in the help text: `run_discover` still has an old initial error string saying “requires an explicit IPv4 target” at `src/main.cpp:120-124`, even though the subsequent parser and success path accept IPv4 or IPv6. The later error text is correct, but the initial usage error should be corrected.

## 12. Performance and scalability audit

The existing benchmark was run successfully using `make benchmark`. It performs five samples and records median wall time, max sample labeled p95, operations per second, and peak RSS. At 10,000 targets, the recorded values were:

| Stage | Median | Max/p95 sample | Peak RSS |
| --- | ---: | ---: | ---: |
| Target expansion | 0.398 ms | 0.811 ms | 5,276 KiB |
| TCP scheduler | 42.488 ms | 55.129 ms | 11,036 KiB |
| UDP scheduler | 41.082 ms | 41.856 ms | 12,904 KiB |
| Service scheduler | 45.431 ms | 46.708 ms | 19,112 KiB |
| OS scheduler, 120,000 logical probes | 544.160 ms | 560.699 ms | 54,044 KiB |
| Full orchestrator, one TCP port | 100.455 ms | 106.557 ms | 54,044 KiB |
| JSON serialization | 5.540 ms | 6.034 ms | 54,044 KiB |
| XML serialization | 2.439 ms | 2.920 ms | 54,044 KiB |

The 100/1,000/10,000 rows show approximately linear growth in the tested offline workloads. The OS stage is intentionally dominant because it executes twelve logical probes per host and retains evidence for matching. The benchmark is valuable as a regression baseline, but it is not a live-network result and does not exercise IPv6 address formatting, IPv6 packet lengths, AF_INET6 sockets, DNS latency, capture rates, or mixed-family correlation. The generated CSV and harness use documentation-space IPv4 hosts and synthetic results.

The stress tests add useful bounded workloads: 10,000 timers, 10,000 correlation entries, 1,000 hosts × 100 TCP ports, 1,000 hosts × 12 OS probes, and Phase 15 mixed-family/IPv6 parser cases. These demonstrate bounded deterministic behavior but do not establish a production throughput SLO. Phase 16 should add mixed-family benchmark rows and record host-count/port-count/RSS relationships explicitly.

## 13. Verification record

The final audit gate sequence completed as follows:

| Gate or check | Result | Notes |
| --- | --- | --- |
| `make clean` | Passed | Clean build directory regeneration. |
| `make all` / production build | Passed | Strict C++20 warning flags. |
| `make test` | Passed | Makefile registers 77 test binaries; AF_PACKET cases skip honestly. |
| `make debug` | Passed | Debug build/test path completed. |
| `make release` | Passed | Release build completed. |
| `make asan` | Passed | No sanitizer failure in the exercised suite. |
| `make ubsan` | Passed | No undefined-behavior failure in the exercised suite. |
| `make coverage` | Passed | Instrumented test gate completed; no threshold report is enforced. |
| `make fuzz` | Clean skip | `clang++` unavailable; no runtime fuzz claim is made. |
| `make benchmark` | Passed | Offline CSV generated for 100/1,000/10,000 targets. |
| AF_PACKET tests | Clean skips | Sandbox returned `Operation not permitted`; no live success was fabricated. |
| CLI matrix | Passed | Mixed family, invalid syntax, output formats, explicit capability errors. |
| `git diff --check` | Passed before audit artifact | No whitespace errors in the implementation revision. |
| prohibited architecture search | Passed | No production second reactor, threads, polling, or sleep loops found. |

The audit report itself is a new uncommitted audit artifact. No implementation file, existing Phase 15 commit, or repository history was altered by the audit.

## 14. Comparison with official Nmap documentation

The comparison is a capability and architecture comparison, not a claim that Skan should reproduce Nmap. Nmap’s official guide describes target enumeration into IPv4/IPv6 addresses, host discovery, reverse DNS, port scanning, version detection, OS detection, traceroute, NSE phases, and output [1] [2]. Nmap documents ICMP, TCP SYN/ACK, UDP, SCTP, ARP/Neighbor Discovery and no-ping/list-scan controls for host discovery [3]. It documents many scan techniques, large port/service datasets, timing controls, and output formats [4]. It documents IPv6 support for popular ping, port, version, and NSE features [5].

| Area | Skan at `d9f63df` | Nmap documented capability | Difference and audit conclusion |
| --- | --- | --- | --- |
| Reactor and lifecycle | One thread-affine epoll `IOEngine`, one timer mechanism, deterministic injected transports | Nmap uses its nsock I/O abstraction and supports platform engines such as epoll, kqueue, poll, and select [6] | Skan is intentionally simpler and more constrained. Its single-reactor rule is a design strength for auditability, not Nmap parity. |
| Target specification | IPv4/IPv6 literals, bounded CIDR/ranges, mixed lists, synchronous A+AAAA, binary dedup/order | Nmap supports IPv4/IPv6 CIDR, `/0`, multiple input forms, input/exclude files, resolve-all/unique controls, reverse DNS, and IPv6 zone IDs [7] | Skan is safer and narrower. It lacks files/exclusions/reverse DNS/zone IDs and rejects large expansions rather than enumerating them. |
| Host discovery | Offline/injected ICMPv4/ICMPv6/TCP, explicit Linux ICMP/TCP/ARP subset | Nmap documents ICMP, TCP SYN/ACK, UDP, SCTP, IP-protocol, ARP, IPv6 ND, list scan, and no-ping [3] | Skan covers a bounded safe subset and explicitly lacks UDP/SCTP/IP-protocol/complete ND parity. |
| TCP scanning | Connect and explicit Linux IPv4 SYN | Nmap documents Connect, SYN, FIN/NULL/Xmas, ACK, Window, Maimon, Idle, IP protocol, FTP bounce, and more [4] | Skan deliberately implements only a small non-evasive subset. |
| UDP scanning | Bounded project-owned probe DB, one scheduler, retries, typed correlation, `OPEN_OR_FILTERED` silence | Nmap has broader UDP probing, rate-limit handling, popular-port data, and version-assisted disambiguation [3] [4] | Skan has honest UDP mechanics but not Nmap-scale database or inference breadth. |
| Service/version detection | Six compact TCP-oriented project probes and bounded matching | Nmap documents about 2,200 well-known service mappings and roughly 6,500 pattern matches for more than 650 protocols, with intensity and rarity [8] | Skan is a compact inventory detector, not a broad version detector. |
| OS detection | Three generic project fingerprints; bounded TCP/ICMP/UDP evidence; IPv6 unavailable | Nmap documents dozens of tests and more than 2,600 OS fingerprints with device/classification/CPE and fuzzy confidence behavior [9] | Skan is materially narrower, and its current capability-honest unavailable state is preferable to overclaiming. |
| Timing | Timing profiles, RTT estimator, congestion/backoff, bounded outstanding work | Nmap documents host groups, adaptive probe parallelism, RTT bounds, retries, host timeout, delay, min/max rate, and T0–T5 templates [6] | Skan has a sound timing seam but fewer user controls and no live mixed-family performance evidence. |
| Output | Normal, JSON, XML, grepable; canonical family/status/error model | Nmap documents interactive, normal, XML with DTD, grepable, script-kiddie, append, resume, stylesheet, and verbosity/debug controls [10] | Skan output is coherent but not Nmap-compatible and lacks resume/multi-file workflow features. |
| Scripting | None; intentionally prohibited from Phase 15 | Nmap NSE is Lua-based, supports discovery/version/vulnerability workflows, structured output, script phases, and script parallelism [11] | This is a deliberate non-goal requiring a separate authorization and sandbox design. |
| IPv6 | Typed identity, offline/Connect parsing and construction, AF_INET6 stream transport; raw/OS/complete ND unavailable | Nmap documents IPv6 support for ping, port, version, and NSE features plus local-link ND behavior [3] [5] | Skan has a credible foundation but not Nmap’s IPv6 feature breadth or raw/ND/OS coverage. |
| Safety posture | Explicit target input, controlled local/injected tests, capability errors, no fallback, no evasion/spoofing/exploitation | Nmap documents additional evasion, spoofing, scripting, and advanced scan features [4] [11] | Skan intentionally rejects a large category of Nmap functionality. This is a product boundary, not a defect. |

## 15. Prioritized Phase 16 roadmap

Phase 16 should begin with integrity and acceptance gaps before adding breadth. The following roadmap preserves the Phase 0–15 architecture and does not assume a second reactor, packet stack, scheduler, or output model.

| Priority | Work item | Acceptance boundary |
| --- | --- | --- |
| P0 | Validate TCP/UDP checksums on received IPv6 and IPv4 observations where the protocol requires it | Shared pseudo-header verification; no checksum-invalid TCP/UDP response reaches a valid correlated result; add odd-length, extension, UDP-zero, and malformed tests. |
| P0 | Hard-cap all user-configurable target and response limits | CLI and library reject values above documented ceilings; reservations are bounded; errors are typed as resource exhaustion. |
| P0 | Correct stale capability/help documentation | Remove AF_INET-only resolver wording and the “explicit IPv4 target” discovery error; add explicit zone-ID and raw-IPv6 limitations to help. |
| P1 | Establish executable fuzzing in CI | Pinned Clang/libFuzzer job runs packet, target, extension, ICMPv6, CLI parser, output, and bounded scheduler harnesses with retained crash artifacts. |
| P1 | Add coverage thresholds and reports | Generate line/branch coverage and enforce minimums for target limits, IPv6 extensions, checksums, receiver statuses, capability errors, and output escaping. |
| P1 | Add controlled IPv6 service integration | AF_INET6 `::1` listener and banner fixtures exercise the real ServiceDetector/ServiceTcpTransport path, conditionally skipped only when IPv6 is unavailable. |
| P1 | Add mixed-family benchmarks | Extend the offline harness with IPv6 and mixed target/address/report datasets and publish revisioned results. Keep live benchmarks private-lab only. |
| P1 | Add asynchronous DNS only if startup latency becomes material | Implement behind the existing resolver seam with explicit cancellation, result limits, deterministic ordering, and no unbounded worker/reactor architecture. A synchronous pre-reactor resolver remains acceptable for small scans. |
| P2 | Define scoped IPv6 addresses safely | Represent address plus validated zone/interface identity. Require explicit interface for link-local live behavior; never strip a zone or select an interface implicitly. |
| P2 | Controlled Linux raw IPv6 lab capability | Separate explicit-interface AF_PACKET send/capture acceptance tests for ICMPv6/TCP/UDP; capability failures remain unavailable with no fallback. Do not begin until checksum and correlation semantics are complete. |
| P2 | Evaluate limited Neighbor Discovery | Only add a complete bounded ND workflow if solicitation/advertisement state, options, timers, link-local scope, malformed input, and resource budgets are specified independently. |
| P2 | Expand service and OS data only with provenance | Add project-owned signatures/fingerprints, validation, confidence calibration, and corpus regression tests. Do not import Nmap data or infer identity from addresses/services. |
| P3 | Richer protocol coverage | Consider additional non-evasive scan types, UDP evidence, or IP protocol support only with typed models, explicit capability reporting, bounded correlation, and controlled fixtures. |
| P3 | Optional scripting/extensibility | Treat as a separate product/security project requiring sandboxing, authorization, resource budgets, API review, and output integration. It is not a small scanner feature. |

## 16. Final assessment

Skan should be described as a **bounded, capability-honest, single-reactor dual-stack scanning foundation** rather than as an Nmap replacement or a complete IPv6 scanner. The Phase 15 implementation is strongest when it says exactly what it can do: parse and normalize typed IPv4/IPv6 targets, construct and inspect bounded IPv6 packets offline, scan IPv4/IPv6 loopback through Connect, detect bounded TCP services over the existing lifecycle, preserve family-aware results, and report unavailable raw/OS capabilities explicitly.

The next phase should close F-01 and F-02 first, then improve executable validation and controlled IPv6 acceptance. Broader Nmap-like capabilities should remain separate, explicitly authorized projects. No evidence from this audit justifies adding evasion, spoofing, decoys, fragmentation attacks, credentials, exploitation, persistence, public-target automation, implicit interface selection, fallback, threads, polling, sleeps, or a second reactor.

## References

[1]: https://nmap.org/book/nmap-phases.html "The Phases of an Nmap Scan"
[2]: https://nmap.org/book/man.html "Nmap Reference Guide"
[3]: https://nmap.org/book/man-host-discovery.html "Nmap Host Discovery"
[4]: https://nmap.org/book/port-scanning-options.html "Nmap Port Scanning Command-line Flags"
[5]: https://nmap.org/book/man-misc-options.html "Nmap Miscellaneous Options and IPv6"
[6]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"
[7]: https://nmap.org/book/man-target-specification.html "Nmap Target Specification"
[8]: https://nmap.org/book/man-version-detection.html "Nmap Service and Version Detection"
[9]: https://nmap.org/book/man-os-detection.html "Nmap OS Detection"
[10]: https://nmap.org/book/man-output.html "Nmap Output"
[11]: https://nmap.org/book/nse.html "Nmap Scripting Engine"


## Phase 16 reconciliation addendum

The historical findings above were used as the Phase 16 acceptance checklist. The implementation now resolves F-01 by validating received IPv4/IPv6 TCP and UDP pseudo-header checksums in `PacketReceiver`, accepting zero IPv4 UDP checksums and rejecting zero IPv6 UDP checksums. It resolves F-02 with hard target and hostname-result ceilings and bounded resolver reservation. F-05 and F-06 are addressed with offline IPv6/mixed benchmark rows, IPv6 receiver parsing measurements, deterministic 10,000-host IPv6/mixed scheduler workloads, and conditional local `::1` HTTP/SSH service integration. F-07 is addressed within a strict scope model: one validated IPv6 zone token is preserved in typed identity and canonical output, numeric/name zones are resolved only explicitly, and unscoped link-local live use is rejected.

The Phase 16 implementation also adds a bounded shared quoted IPv6/UDP parser for ICMPv6 error correlation, typed IPv6 interface inventory and family capability reporting, scoped Connect/service construction, typed SYN construction and assessment, shared-parser adoption across legacy validators, and mixed-family orchestrator coverage. Native Linux raw IPv6 discovery/SYN/UDP, complete Neighbor Discovery, and IPv6 OS fingerprinting remain explicitly unavailable because a complete source-selection, neighbor-resolution, capture/injection, and reliable-evidence design was not safely completed. The code does not claim those capabilities and does not fall back to another transport.

The full registered test suite passed after the implementation. AF_PACKET-dependent tests skipped cleanly with `Operation not permitted`; `make fuzz` remains a clean skip when `clang++` is unavailable. All Phase 16 inputs remain local, documentation-space, synthetic, or injected. No public-target traffic, evasion, spoofing, exploitation, credential handling, persistence, or stealth behavior was introduced.
