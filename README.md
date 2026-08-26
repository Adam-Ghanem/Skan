# Skan

Skan is an original, modular, **Nmap-inspired, Linux-first network-scanning engine** under development. It is inspired by general scanner engineering principles, but it does not copy other scanner source code, claim Nmap equivalence, or claim compatibility with any other scanner.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, asynchronous I/O engine, packet layer, host discovery, scan engine, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides reusable infrastructure, a scoped host-discovery engine, TCP port scanning, service detection, a capability-honest OS fingerprinting architecture, a Phase 10 explicit Linux transport integration, a Phase 11 unified scan orchestrator, a Phase 12 target-resolution engine, a Phase 14 live OS fingerprinting engine, and the Phase 15 capability-honest IPv6 foundation and dual-stack offline/connect extension; it does not claim a full unrestricted scanning workflow.

## Language and platform

The primary implementation language is **C++20**. C11 is reserved for selected low-level or system-facing primitives where a C boundary provides a real benefit. The repository includes a small C status API to demonstrate that boundary. Lua 5.4 and TypeScript/React remain planned future technologies.

Skan targets Linux. Phase 1 uses Linux `epoll` as its I/O backend. Phase 3 uses `std::chrono::steady_clock` deadlines and the Phase 1 timer API. Future backends such as BSD `kqueue` or Windows IOCP are not implemented.

## Development status

| Phase | Status |
| --- | --- |
| Phase 0 — Foundation | **COMPLETE** |
| Phase 1 — I/O Engine | **COMPLETE** |
| Phase 2 — Packet Layer | **COMPLETE** |
| Phase 3 — Host Discovery | **COMPLETE** |
| Phase 4 — Scoped TCP Port Scan | **COMPLETE** |
| Phase 5 — Service Detection | **COMPLETE** |
| Phase 6 — OS Fingerprinting Architecture | **COMPLETE** |
| Phase 7 — Adaptive Timing + Scan Engine | **COMPLETE** |
| Phase 8 — Output + Result Serialization | **COMPLETE** |
| Phase 10 — Real Network Scan Integration | **COMPLETE** |
| Phase 11 — Unified Scan Orchestrator and audit hardening | **COMPLETE** |
| Phase 12 — Target Resolution and Target Engine | **COMPLETE** |
| Phase 13 — Bounded UDP Scan Engine | **COMPLETE** |
| Phase 14 — Live OS Fingerprinting Engine | **COMPLETE** |
| Phase 15 — IPv6 Foundation and Dual-Stack Extension | **COMPLETE** |
| Phase 16 — Production Dual-Stack IPv6 Completion | **COMPLETE** |
| Phase 19 — Production Network Capability Completion and Dual-Stack Validation | **COMPLETE** |
| Phase 20 — Production-Grade Scan Engine Hardening | **COMPLETE** |
| Phase 21 — Production Live-Network Validation and Capability-Honest Hardening | **COMPLETE** |
| Phase 22 — Production Live Scanning Engine and capability-honest raw hardening | **COMPLETE** |

Phase 3 began with normalized IPv4 targets; Phase 15 extends the same boundary to typed IPv4/IPv6 identities. Phase 12/15 now own strict target parsing, bounded CIDR/range expansion, platform A+AAAA resolution, deduplication, and deterministic family-aware ordering before discovery or scanning begins. Its default transport remains a deterministic recording transport for offline tests and safe CLI exercises, while Phase 10 adds an explicit Linux transport option. For Linux raw mode, Phase 22 derives an interface only from target-family source and route evidence when `--interface` is omitted; explicit interfaces remain supported and no raw mode is selected implicitly. Phase 5 consumes only OPEN TCP results, performs bounded service probes through the same pipeline boundary and Phase 1 reactor, and uses a small project-owned database. Phase 6 adds the OS fingerprinting architecture and Phase 14 adds deterministic live-capable packet probes, bounded evidence collection, and an explicit Linux raw-packet transport; capability failures remain visible and never fall back silently. Phase 10 adds real ICMP/TCP/ARP discovery adapters under the same explicit interface boundary. No public Internet target is used by the test suite.

## Phase 3 Host Discovery

The discovery flow is:

```text
core::Target
    ↓
DiscoveryScheduler
    ↓
DiscoveryProbe
    ↓
Phase 2 packet serialization
    ↓
DiscoveryTransport
    ↓
Phase 1 IOEngine timers/event loop
    ↓
response correlation
    ↓
DiscoveryResult and HostState
```

`DiscoveryScheduler` accepts the existing `core::Target` value and its already-resolved `core::Host` values. It does not add a second target or CIDR parser. Each host is validated through the typed binary address boundary before probe construction. Production or lab integrations supply their own explicit target set and transport.

The scheduler supports concurrent ICMP Echo, TCP, and ARP probe strategies with a configurable maximum outstanding count. It keeps bounded work in a queue, assigns deterministic `ProbeId` values, records submission metadata, schedules one-shot deadlines on the shared Phase 1 `IOEngine`, and removes completed or expired probes from the pending map.

| Probe | Submission and evidence | Current transport status |
| --- | --- | --- |
| ICMP Echo | Reuses Phase 2 `ICMP` or `ICMPv6` Echo Request serialization. Matches Echo Replies by typed target address, identifier, and sequence. | Offline by default; explicit-interface Linux IPv4/IPv6 raw branch; IPv6 non-loopback requires a resolvable explicit neighbor path |
| TCP | Reuses Phase 2 `TCP` serialization, including IPv6 pseudo-header checksums, for an explicit configured port. Classifies matching SYN/ACK or RST responses as positive reachability evidence. | Offline by default; explicit-interface Linux IPv4/IPv6 raw branch; IPv6 non-loopback requires a resolvable explicit neighbor path |
| ARP | Uses a minimal discovery-local 28-byte ARP representation for IPv4 Ethernet request/reply construction and parsing. | Offline by default; explicit Phase 10 Linux adapter on selected Ethernet interfaces |

The default TCP discovery port is **80**, centralized in `kDefaultTcpDiscoveryPort`. The default timeout is **1000 ms**, and the default outstanding-work limit is **64**. These are discovery-policy defaults, not a port-scanning range; Phase 3 never enumerates ports.

## Correlation, timeout, and state policy

Every submission carries a `ProbeId`, target address, probe type, packet bytes, and protocol-specific correlation fields. ICMP uses a deterministic identifier and sequence derived from the probe ID. TCP uses a deterministic source port and sequence number and requires the response source/destination ports to match. ARP correlates the target IPv4 address, operation, and sender/target IPv4 fields.

The scheduler measures sent and received times with `std::chrono::steady_clock`. Successful responses expose RTT in milliseconds. A malformed response is recorded as evidence and completes the corresponding probe; an unrelated response is ignored without disturbing pending work. A response for an expired probe is classified as late and cannot change host state. A response for a completed probe is counted as a duplicate and cannot create another result.

Host aggregation is deterministic. Any positive response produces `UP`, even if another probe timed out. An explicit `DOWN` result would take precedence over `UNKNOWN` only when no positive evidence exists. A timeout or lack of conclusive evidence produces `UNKNOWN`; non-response is never treated as proof that a host is down.

## Phase 4 Scoped TCP Port Scan

The Phase 4 port scanner accepts already-resolved `core::Target` and `core::Host` values and validates every host before queueing any port. The CLI accepts normalized IPv4 and IPv6 targets from the Target Engine; it does not add a public-target default.

Only TCP is supported. `--tcp-ports` accepts a single port, a comma-separated list, or an inclusive range such as `22,80,443,8000-8002`. Values are validated to `1..65535`, sorted, and deduplicated. With no explicit selection, the scanner uses the small default set `{22, 80, 443}` and never silently enumerates all 65535 ports.

The scheduler is bounded by `max_outstanding`, uses the shared Phase 1 `IOEngine` for epoll events and one-shot timers, and retains deterministic target/port/probe ordering. TCP Connect uses actual nonblocking AF_INET or AF_INET6 sockets and classifies immediate success or `SO_ERROR==0` as `OPEN`, `ECONNREFUSED` as `CLOSED`, and deadline expiry as `FILTERED`; other local socket failures are `UNKNOWN`. Socket events, timers, and descriptors are removed or closed on every terminal path.

The TCP SYN probe reuses the Phase 2 `packet::TCP` model for deterministic offline construction and validates source/destination addresses and ports, SYN/ACK acknowledgment correlation, and RST responses. The explicit Linux transport path can perform a real capability-gated SYN scan when the user selects `--transport linux --interface <name>` and the host permits AF_PACKET; otherwise the result is an explicit capability failure or deterministic offline result, never an implicit fallback.

The minimal CLI is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80,443 --method connect \
  --timeout-ms 500 --max-outstanding 16
```

`--method syn` is accepted as a capability-gated mode and exits without network activity when the raw-packet capability is unavailable. Alternate TCP evasion modes, decoys, spoofing, fragmentation tricks, scripting, dashboards, and bypass mechanisms remain outside scope; Phase 14 adds the bounded OS fingerprinting path described below. Phase 5 service detection is opt-in and limited to bounded TCP banner/probe matching on OPEN results.

## Phase 5 Service Detection

Phase 5 is an opt-in service-detection layer that consumes only `PortResult` values whose state is `OPEN` and whose protocol is TCP. It does not rescan ports, infer service identity from port numbers alone, perform UDP probes, or run operating-system fingerprinting. The CLI performs service probes only after typed IPv4/IPv6 target validation.

The detector uses the shared Phase 1 `IOEngine` for nonblocking connect, writable, readable, hangup, and timeout events. Its `ServiceScheduler` bounds active probes with `max_outstanding`, bounds each response with `max_response_bytes`, limits attempts per port with `max_probes`, and retains deterministic target/port/probe ordering. Partial TCP responses are accumulated until a matcher succeeds, the peer closes, the response limit is reached, or the shared deadline expires.

Probe definitions are project-owned and stored in `data/service-probes.db` using a compact line-oriented format. Each definition names a TCP payload and one or more prefix, substring, or regular-expression rules. Regex rules may expose numbered captures as `$1`, `$2`, and so on for product and version fields. The built-in dataset is intentionally small and covers HTTP, SSH, FTP, SMTP, a TLS greeting, and a generic banner fallback; it is not an imported Nmap database.

A `ServiceResult` retains the target, TCP port, inherited port state, detection state, service, product, version, extra text, confidence, method, probe name, optional RTT, error classification, and completion timestamp. Matching is deterministic: the highest confidence wins, followed by rule specificity and declaration order. No-match, timeout, connection-closed, oversized-response, malformed, invalid-target and transport-error outcomes remain explicit rather than being converted into guessed service identities.

The CLI extension is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --method connect \
  --timeout-ms 500 --max-outstanding 16 --service-detect \
  --max-response-bytes 8192 --max-probes 2
```

An explicit project-owned database may be selected with `--service-db data/service-probes.db`. Service detection is performed only after the port scan completes, and only OPEN TCP results enter the service scheduler. Phase 5 itself intentionally does not claim protocol-complete identification, TLS negotiation, credential handling, service exploitation, UDP detection, or Internet-wide scanning; live OS fingerprinting is implemented separately in the Phase 14 path below. Phase 5 is complete for this bounded banner/probe scope.

## Phase 6 OS Fingerprinting Architecture

Phase 6 separates **evidence collection**, **runtime data**, **deterministic matching**, and **orchestration**. `OSDetector` consumes an existing `core::Target` plus Phase 4 `PortResult` values and optional Phase 5 service results only to choose usable TCP context; it never derives an operating-system identity from a port number or service label. The scheduler prefers a known OPEN TCP port and otherwise uses the configured explicit probe port for injected/offline work.

The execution path is:

```text
Phase 4 PortResult / optional Phase 5 context
                    ↓
              OSDetector
                    ↓
              OSScheduler
                    ↓
  bounded TCP SYN/ACK/FIN/NULL/XMAS variants, closed variants, ICMP echo, UDP fingerprint
                    ↓
          OSProbeTransport seam
             ↙                 ↘
 RecordingOSProbeTransport   LinuxOSProbeTransport (explicit AF_PACKET)
             ↓
 Phase 1 IOEngine timers and bounded pending map
                    ↓
 packet correlation and OS evidence extraction
                    ↓
 project-owned os-fingerprints.db
                    ↓
 weighted available-evidence OSMatcher
                    ↓
 ranked OSDetectionResult
```

The runtime data file `data/os-fingerprints.db` is intentionally a small Skan-owned laboratory dataset, not a copied broad fingerprint corpus. It supports comments, blank lines, optional Class metadata, typed numeric and boolean fields, bounded numeric ranges, TCP option ordering, UDP payload/response behavior, response-presence rules, duplicate detection, missing metadata rejection, and deterministic declaration ordering. Both the CLI and library loader use this project-owned runtime file; no broad external fingerprint corpus is embedded in C++. IPv6 probe evidence uses the same typed submission/response boundary and is admitted only after exact binary identity and protocol correlation.

Matching uses only fields in `Observed` state. Absent, timed-out, unsupported, and unavailable fields contribute no penalty; observed mismatches reduce confidence. The current weights emphasize TCP option ordering, window, and transport values while retaining TTL, DF, MSS, window scale, SACK, timestamps, flags, behavior, and ICMP evidence. IPv6 observations do not reuse IPv4 header-only assumptions and do not mix families within a target’s evidence. Results are categorized as `NO_MATCH` below `0.30`, `LOW` from `0.30` to below `0.60`, `POSSIBLE` from `0.60` to below `0.85`, and `STRONG` at or above `0.85`. Top-N output is sorted by descending confidence and then fingerprint name.

Probe and scheduler states remain explicit: `Generated`, `Sent`, `ResponseReceived`, `Timeout`, `Unsupported`, and `Malformed`. TCP SYN, ACK, FIN, NULL, and XMAS variants, ECN flags, closed-port variants, ICMP Echo, UDP fingerprint, and UDP Port Unreachable probes are available to the model. Offline recording and injected transports exercise every probe family; the Linux transport uses typed IPv4 or IPv6 addresses from the selected interface and the shared capture/reactor lifecycle. `UNAVAILABLE` is returned only when the selected live capability cannot be opened, and no OS identity is inferred from local host information. Unit, integration, stress, and capability-aware tests inject serialized packet responses and never require public targets or public traffic.

The minimal CLI form is:

```sh
./bin/skan os-detect 192.0.2.10 --os-db data/os-fingerprints.db \\
  --timeout-ms 500 --max-outstanding 8 --json
```

The default `os-detect` transport is deterministic offline mode and records bounded probe timeouts without network traffic. `--transport linux --interface <name>` explicitly selects the live AF_PACKET path; permission, interface, capture, and injection failures are reported as `UNAVAILABLE` evidence without fallback. Injected transports remain the deterministic test path.

## Phase 7 Adaptive Timing + Scan Engine

Phase 7 adds Skan’s own protocol-agnostic, event-driven adaptive timing layer. The validated implementation is complete for the offline and opt-in integration scope described here. It is implemented in `scanengine` and controls scheduling policy rather than TCP, ICMP, UDP, service, or OS packet formats. `TimingProfile` provides named Skan profiles `T0` through `T5`, with `T3` as the stable default. Each profile defines minimum, maximum, and initial parallelism, timeout bounds, RTT multiplier, timeout backoff threshold, recovery threshold, EWMA loss alpha, and bounded retries.

`RttEstimator` accepts only valid correlated response samples. Its first sample initializes `SRTT = RTT` and `RTTVAR = RTT / 2`; later samples use configurable alpha and beta EWMA updates, and `RTO = SRTT + multiplier × RTTVAR`. RTO values are clamped to the profile’s configured timeout bounds. Timeouts, duplicates, late responses, and malformed responses affect lifecycle or congestion accounting but do not create RTT samples.

`CongestionController` tracks bounded current parallelism, response and timeout counts, consecutive outcomes, backoff count, and an EWMA drop estimate. Repeated timeouts reduce parallelism by the configured backoff factor after the configured threshold. Repeated successes increase it by one after the recovery threshold. All changes remain within the configured minimum and maximum; a single timeout does not necessarily halve concurrency.

`ScanGroup` owns an independent generic queue of `ScanWorkItem` values. Work items contain an ID, target string, protocol metadata, timestamps, deadline, retry count, and one of `QUEUED`, `SUBMITTED`, `COMPLETED`, `TIMED_OUT`, `CANCELLED`, or `FAILED`. `AdaptiveScheduler` borrows an existing Phase 1 `IOEngine`, uses one-shot shared timers, maintains a bounded pending map, and accepts an injected protocol-agnostic `ScanTransport`. It handles completion, timeout, retry, cancellation, shutdown, duplicate, late, malformed, and transport-failure events without threads, sleeps, busy loops, or a second reactor.

`TimingController` is the integration seam used by Phase 4 TCP port scanning, Phase 5 service detection, and Phase 14 OS detection when their new `adaptive_timing` configuration flag is enabled. The original static timeout, concurrency, retry, and transport defaults remain unchanged when the flag is false. TCP Connect transport remains nonblocking and unchanged at the transport layer; TCP SYN remains capability-limited/injected; service matching and OS evidence matching remain protocol-specific. The adaptive layer supplies concurrency, timeout calculation, RTT feedback, bounded retries, and metrics without inferring protocol results.

The scan CLI exposes the controls on `scan` without expanding target scope:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80,443 \\
  --method connect --timing T3 --max-outstanding 64 \\
  --min-parallelism 2 --max-parallelism 32 --retries 1
```

Invalid profile, parallelism, timeout, or retry values are rejected. `--retries 0` is valid and remains the conservative default. There is still no implicit `1–65535` port scan. The OS detection command retains capability-honest explicit status reporting and supports the Phase 14 Linux raw-packet path only when selected with an interface.

`ScanMetrics` records queued work, submitted attempts, completed/timed-out/failed/cancelled work, duplicate/late/malformed responses, current and maximum observed parallelism, current/minimum/maximum/average RTT, timeout and retry counts, EWMA drop rate, and elapsed time. Deterministic tests cover the RTT equations and bounds, congestion backoff/recovery, queue and state transitions, retries, cancellation, shared IOEngine timers, multi-group independence, Phase 4 scheduler integration, and a 1000-item offline stress run. No network traffic is generated by the Phase 7 tests.

## Phase 8 Output + Result Serialization

Phase 8 adds a pure presentation layer. It consumes a canonical typed `output::ScanReport` assembled from existing Phase 3–7 result types and performs no scanning, probing, packet construction, detection, scheduling, timing, or network I/O. The `HostResult` model retains discovery state, optional hostname/RTT, `PortResult` values, `ServiceResult` values, ranked `OSMatchResult` values, and warnings/errors. Top-level metadata retains scanner identity, optional timestamps/duration, target specification, timing profile/metrics, and report warnings/errors.

`calculate_summary()` derives host, port, service, and OS counts from the contained result vectors rather than trusting duplicated counters. Optional values remain absent; empty strings, zero, false, unknown state, and no OS matches are distinct representations. Invalid confidence, duration, RTT, empty required identifiers, and non-finite values are rejected with structured `OutputStatus::InvalidReport`.

All writers implement the same `OutputWriter` interface and are independently usable. `OutputManager` only selects a writer; format-specific serialization remains in its own class:

| Format | Behavior |
| --- | --- |
| Normal | Stable terminal-oriented report with hosts, ports, services, OS matches, derived summary, warnings, and errors. Unavailable optional fields are omitted. |
| JSON | UTF-8-preserving standards-compliant JSON with stable key/array order, correct control/quote/backslash escaping, and absent optional fields omitted. |
| XML | Deterministic UTF-8 XML with escaped attributes/text, stable ordering, and omitted optional elements. |
| Grepable | One logical record per line using fixed `Scan:`, `Host:`, `Port:`, `Service:`, `OS:`, `Warning:`, `Error:`, and `Summary:` records with fixed field ordering. Quoted values use backslash escaping for quotes, backslashes, tabs, carriage returns, and newlines. |

Hosts are sorted by canonical address, ports by numeric port and protocol, services by associated port, and OS matches by descending confidence followed by ascending name. Repeated serialization of one report is byte-identical. Untrusted banner/product/version data is escaped or control-sanitized in every format; machine formats never emit terminal color codes.

The scan CLI accepts `--output normal|json|xml|grepable` and defaults to `normal`. `-o <file>` and `--output-file <file>` serialize completely before writing through a securely created same-directory temporary file, flush and sync it, and atomically rename it over the selected path. File-open, serialization, and replacement failures are reported on stderr and do not create a partial success message on stdout. Standard output contains only the selected serialization; operational logs and diagnostics go to stderr. Existing `--version`, target validation, port selection, service detection, OS capability behavior, and Phase 7 timing flags remain additive and unchanged.

Examples:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output normal
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output xml
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output grepable
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json -o scan.json
```

The grepable schema is intentionally small and script-friendly. `Port` records contain `target`, `number`, `protocol`, `state`, `probe`, `reason`, and optional `rtt_ms`; `Service` records contain target/port/protocol/state/port-state, optional identity fields, confidence, method, and error; `OSStatus` records contain address, state, error, confidence, probe counters, and evidence counts; `OS` records contain address, name, confidence, and class. `Summary` contains derived host, port, service, and OS counts. No writer reconstructs information from another writer.

## Phase 9 Network Transport + Packet Capture

Phase 9 adds infrastructure for connecting future packet-producing and packet-consuming components to Linux interfaces. It does not add a new scan mode. The `net` module is divided into interface discovery, byte transport, bounded packet capture, packet observation, small protocol/port filtering, and a reusable correlation-table boundary.

`NetworkInterface` contains the kernel interface name, index, IPv4 addresses with prefix lengths, operational state, and separate capture/injection capability flags. Linux enumeration uses standard interface APIs, returns structured `InterfaceStatus` errors through `enumerate_interfaces_result()`, and returns interfaces in deterministic name order. `find_interface()` performs exact-name lookup. Skan never silently selects an interface for privileged packet injection; callers must explicitly provide `TransportConfig::interface_name` or `CaptureConfig::interface_name`.

`Transport` moves only already-serialized bytes. `RecordingTransport` records exact frames without network access or privileges, and `NullTransport` accepts configuration while intentionally transmitting nothing. `LinuxTransport` uses an explicitly selected Linux `AF_PACKET` socket, has an explicit open/close lifecycle, preserves system errors, uses nonblocking send behavior when configured, and owns its descriptor through a move-only RAII wrapper. It never chooses ports, creates packets, modifies source identity, fragments frames, or implements evasion.

`PacketCapture` is independent from scan strategy. `LinuxCapture` uses an explicitly selected, nonblocking `AF_PACKET` socket and bounded `recvmsg(MSG_TRUNC)` reception, so oversized frames are reported instead of being silently accepted. `RecordingCapture` supplies deterministic synthetic frames to tests. `PacketReceiver` copies only bounded frames and passes them through the existing Phase 2 Ethernet, IPv4, TCP, UDP, and ICMP parsers, preserving deterministic timestamps and distinguishing truncation, malformed data, unsupported protocols, and valid observations. Its descriptor can be attached to the existing Phase 1 `IOEngine`; no second reactor, polling thread, or blocking receive loop is introduced.

`PacketFilter` supports only the small protocol and source/destination-port predicates required before future correlation. `CorrelationTable` provides deterministic insertion, duplicate detection, lookup, removal, late-packet rejection, and deadline cleanup. It is a reusable boundary rather than a scanner or packet strategy.

The infrastructure-only CLI command is:

```sh
./bin/skan interfaces
./bin/skan interfaces --json
./bin/skan interfaces --interface lo --json
```

Normal output lists interface name, index, IPv4 and typed IPv6/prefix values (including link-local zones), state, and family-specific capture/injection capability. JSON output uses stable interface and address ordering and contains only interface data. A missing raw-socket privilege is reported as unavailable capability in the listing or as a structured `PermissionDenied` result when opening a Linux transport or capture backend; no fake successful transmission or fabricated packet response is produced.

> Skan's network transport is capability-honest. When packet capture or injection is unavailable, Skan reports the unavailable capability and does not fabricate successful network operations or packet responses.

Linux AF_PACKET support is Linux-specific and normally requires the privileges permitted by the host's network policy. The controlled integration test uses only the local loopback interface and reports `SKIPPED` when the environment lacks the required capability. Phase 9 does not implement stealth or decoy scanning, source spoofing, evasion, IDS/IPS bypass, fragmentation attacks, credential handling, exploitation, persistence, Internet-wide scanning, or public-target traffic.

## Phase 10 Real Network Scan Integration

Phase 10 connects the existing Phase 4 scheduler to the Phase 9 Linux transport and capture layers without rewriting probe construction, response classification, adaptive timing, or Phase 8 serialization. `LinuxNetworkScanTransport` implements the existing `portscan::PortScanTransport` callback contract and owns the lifecycle of an explicit-interface Linux transport, capture, bounded `PacketReceiver`, and correlation entries. The adapter wraps the Phase 2 TCP SYN segment in an Ethernet/IPv4 frame, recalculating the transport checksum through the existing `packet::Packet` composition path; it does not duplicate TCP serialization.

The capture descriptor is registered with the existing Phase 1 `IOEngine`. A capture callback performs one bounded nonblocking receive, applies the Phase 9 TCP filter, validates target/source addresses, ports, and SYN sequence/acknowledgment correlation, and forwards only a matching `PortResponse` to `PortScanScheduler`. Unrelated packets do not complete probes and do not update adaptive timing. Scheduler timers continue to provide timeout, retry, backoff, and result completion semantics.

`LinuxDiscoveryTransport` provides the analogous explicit-interface path for Phase 3 ICMP Echo, TCP, and dedicated ARP submissions. It feeds existing `DiscoveryResponse` values back through `Discovery::receive()`, preserving `UP` only for matching real responses and `UNKNOWN` for timeout. ARP requests use the existing `discovery::ArpMessage` model and broadcast Ethernet destination; IP packet destinations require a known local neighbor entry unless the selected interface is loopback. The existing service detector remains on its normal nonblocking TCP stream transport because service probes are stream exchanges, not raw packet scans. The OS detector remains capability-honest and reports unavailable/empty evidence when a supported live probe transport is not available; no OS result is inferred from the host platform.

Transport selection is explicit:

```sh
# Existing real Connect path; no raw interface is needed.
./bin/skan scan 127.0.0.1 --method connect --tcp-ports 80

# Deterministic offline path; never opens a network descriptor.
./bin/skan scan 127.0.0.1 --transport offline --method syn --tcp-ports 80

# Real raw-packet SYN path; requires explicit interface and host capability.
./bin/skan scan 127.0.0.1 --transport linux --interface lo \
  --method syn --tcp-ports 80

# Real ICMP/TCP/ARP discovery path; requires explicit interface.
./bin/skan discover 127.0.0.1 --transport linux --interface lo --icmp
```

SYN raw-packet mode without `--transport` and `--interface` fails before scanning. Linux mode never silently falls back to Connect, and Connect mode never silently changes to AF_PACKET. `PermissionDenied`, `InterfaceNotFound`, `NotSupported`, and system failures are printed as diagnostics rather than converted into `OPEN`, `UP`, service identities, or OS matches.

The Phase 10 implementation uses only the one existing reactor, bounded outstanding work, deterministic RAII descriptor ownership, explicit callback detachment, and local controlled test targets. It does not add thread-per-host, thread-per-packet, blocking receive loops, public-target defaults, host-range expansion, source spoofing, evasion, exploitation, credentials, persistence, or authorization behavior.

## Phase 2 Packet Layer

The packet layer remains below discovery and is responsible for protocol representation, validation, deterministic serialization, checksums, and lightweight parsing. Discovery does not duplicate ICMP or TCP packet construction. Packet elements continue to serialize into caller-provided `std::span<std::uint8_t>` buffers and provide owned-vector convenience forms.

| Element | Current support |
| --- | --- |
| Ethernet II | Destination/source MAC, EtherType, fixed 14-byte header, validation, parsing |
| IPv4 | Version 4, fixed 20-byte header, fields, addresses, checksum, parsing |
| IPv6 | Strict 40-byte base header, traffic class/flow label, payload bounds, addresses, parsing |
| IPv6 extensions | Bounded recognition of Hop-by-Hop, Routing, Fragment, and Destination Options headers with typed malformed/unsupported/budget outcomes |
| TCP | Ports, sequence/acknowledgment numbers, flags, supported options, payload, IPv4 and IPv6 pseudo-header checksums, parsing |
| UDP | Ports, derived length, payload, IPv4 and IPv6 pseudo-header checksums, parsing |
| ICMPv4 / ICMPv6 | Echo messages, bounded error/limited Neighbor Discovery forms, family-specific checksums, parsing |
| Packet | One shared Ethernet → IPv4/IPv6 → TCP/UDP/ICMPv4/ICMPv6 composition path and offline serialization |

## Requirements

A Linux environment with GNU Make, GCC, and G++ is required. Normal builds use C++20/C11, `-O2`, and the repository's strict warning flags. Debug builds use `-g -O0`. The Phase 1 backend requires Linux epoll.

## Build

Build the executable with:

```sh
make
```

The executable is written to `bin/skan`. Object files, dependency files, and test binaries are written below `build/`; generated files are not placed in `src/` or `include/`.

For a debug build, use:

```sh
make debug
```

## Tests

Compile and execute all Phase 0 through Phase 14 tests with:

```sh
make test
```

The suite includes deterministic unit tests for discovery and port-selection parsing; TCP Connect and TCP SYN probe classification; Phase 2 TCP packet reuse; service database parsing; prefix, substring, and regex matching; bounded service scheduling; partial responses; malformed, oversized, duplicate, and late responses; invalid-target handling; timer-registration failures; timeouts; retries; multiple targets; and stress-sized synthetic scans. Phase 6 adds owned OS database parser tests, typed observation and weighted matcher tests, packet-backed probe correlation tests, bounded multi-host scheduler tests, and injected detector integration tests. Controlled local integration tests exercise real loopback TCP Connect and real SSH/HTTP banner detection without using public targets. Phase 9 adds deterministic interface, offline transport/capture, packet receiver attach/detach and stale-registration tests, filtering, 10,000-entry correlation stress, Linux lifecycle, and controlled loopback capability tests. Phase 10 adds Linux adapter lifecycle, explicit transport selection, real discovery adapter, and capability-dependent raw-scan tests. Phase 11 adds unified-pipeline, cancellation, stage-order, discovery, 1,000-host × 100-port offline orchestration, and 10,000-timer coverage. Phase 12 adds strict target-parser, exact CIDR/range expansion, bounded hostname resolution seams, deduplication, numeric ordering, resource-limit, resolver-failure, and CIDR-to-orchestrator integration tests. Existing Phase 0–11 tests remain active.

The Makefile provides reproducible build and analysis targets:

```sh
make release
make debug
make asan
make ubsan
make coverage
make fuzz
```

`asan` enables AddressSanitizer with leak detection, `ubsan` enables UndefinedBehaviorSanitizer, and `coverage` builds the complete offline test suite with coverage instrumentation. `fuzz` builds the offline libFuzzer parser harness when `clang++` and its fuzzer runtime are available; otherwise it reports `SKIPPED` without failing the build. The fuzz harness exercises Ethernet, IPv4, TCP, UDP, ICMP, service-database, OS-database, OS probe construction/assessment, port-selection, timing-profile, and target-spec parsing entirely in memory.

## CLI usage

The CLI remains intentionally small. Phase 0 commands are preserved:

```sh
./bin/skan --version
./bin/skan --help
```

Phase 3 adds a loopback-scoped discovery exercise:

```sh
./bin/skan discover 127.0.0.1 --icmp --timeout-ms 10
./bin/skan discover 127.0.0.1 --tcp --tcp-port 80 --timeout-ms 10
```

The discovery CLI uses the offline recording transport. It reports `UNKNOWN` when no synthetic response is injected; it does not open a raw socket or connect to the target. ARP is available to the packet/probe unit tests and future lab transports, but the CLI does not claim an Ethernet interface.

Phase 4 adds the TCP Connect exercise:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 1,22,80 --method connect --timeout-ms 100
```

Phase 5 adds opt-in service detection after OPEN TCP results:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --method connect \
  --service-detect --service-db data/service-probes.db
```

Phase 6 adds a capability-honest OS detection command:

```sh
./bin/skan os-detect 192.0.2.10 --os-db data/os-fingerprints.db \
  --timeout-ms 500 --max-outstanding 8
./bin/skan os-detect 192.0.2.10 --json
```

The default offline form runs the bounded probe scheduler without network traffic and reports explicit `PARTIAL` evidence when no responses are injected. Add `--transport linux --interface <name>` to request live raw packets; capability failure is reported as `UNAVAILABLE` with zero confidence, never as a fabricated match.

Phase 8 adds deterministic output selection for `scan`, Phase 9 adds infrastructure interface inspection, and Phase 10 adds explicit real/offline transport selection:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output normal
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output xml
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output grepable
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json --output-file scan.json
```

The default is `normal`. `-o` and `--output-file` explicitly replace the selected file; serialized results remain separate from stderr diagnostics. Invalid output formats fail before scanning.

The `interfaces` command does not scan or transmit; it reports the interfaces visible to the current Linux environment. `scan --method connect` retains normal TCP sockets without requiring an interface. `scan --method syn` requires explicit `--transport offline` or `--transport linux --interface <name>`, while `discover --transport linux` also requires an explicit interface. Unknown or incomplete arguments print a clear error and return a non-zero status. There is no hidden target-selection path, implicit public-target default, alternate TCP flag option, or full-port-range default.

## Phase 11 — Unified scan orchestrator

Phase 11 adds the production scan entry point that coordinates the existing Phase 0–10 subsystems without replacing them. `ScanOrchestrator` owns a `ScanPipeline`, and each `ScanSession` owns exactly one Phase 1 `io::IOEngine`. The pipeline runs the stages in a deterministic order: **Discovery → Port Scan → UDP Scan (when explicitly requested) → Service Detection → OS Detection → Output**. Discovery, service detection, and OS detection are optional; port scanning remains the normal scan operation unless configuration validation rejects the selected combination.

### Configuration and transport selection

`ScanConfig` is the typed boundary for targets, transport selection, probe method, ports, timing, concurrency, service limits, database paths, and output settings. An empty port list means the existing Phase 4 default TCP port set. The default scan uses TCP Connect, no discovery, no service detection, no OS detection, the Phase 7 timing profile, normal output, bounded timeout and parallelism, and no output file. Explicit `--transport offline` selects deterministic recording transports. Explicit `--transport linux` selects the Phase 10 Linux adapters and requires the relevant interface and raw-packet capability; failures are returned clearly and never silently downgraded to offline behavior.

The orchestrator receives normalized explicit IPv4 hosts from the Phase 12 Target Engine. It does not parse CIDR, ranges, hostnames, or comma-separated input itself, and it does not add Internet-wide scanning, worker threads, polling loops, sleeps, or a second event loop. Bounded asynchronous work remains inside the existing discovery scheduler, port scheduler, service detector, OS detector, transports, and timing controllers.

| Scan option | Meaning |
| --- | --- |
| `--discovery` / `--no-discovery` | Enable or skip the discovery stage; skipping is the default. |
| `--method connect` / `--method syn` | Select the existing TCP Connect or capability-gated SYN method. |
| `--transport offline` / `--transport linux` | Select deterministic recording behavior or explicit Phase 10 Linux networking. |
| `--service-detect` | Run bounded TCP stream service detection only for OPEN ports. |
| `--os-detect` | Run the existing OS detection seam; unavailable live capability produces no fabricated matches. |
| `--adaptive-timing` and timing bounds | Enable or configure the existing Phase 7 timing profile and bounded concurrency controls. |
| `--output normal\|json\|xml\|grepable`, `-o` | Select the existing Phase 8 writer and optionally replace an output file through RAII. |

### State, events, cancellation, and reports

The session state machine explicitly represents initialization, each operational stage, serialization, completion, failure, and cancellation. Typed events identify scan start, stage start/completion, warnings, errors, serialization, completion, and cancellation. Event emission is deterministic and guarded after terminal states. Cancellation is cooperative and idempotent: active schedulers and transports are released through their existing cancellation/destructor paths, the session retains a valid partial canonical report, and output still crosses the existing `OutputManager` boundary.

`ScanReportBuilder` is the only Phase 11 mapping layer from existing discovery, port, service, and OS result types to the canonical Phase 8 `output::ScanReport`. Output formats are not reimplemented in the orchestrator. stdout contains serialized machine output when requested, while diagnostics remain on stderr. Discovery timeouts remain `UNKNOWN`; OS detection does not fabricate a result when live fingerprint transport is unavailable, leaving matches empty and confidence zero while recording a warning.

### Testing and capability behavior

Phase 11 includes unit coverage for configuration validation, state transitions, session ownership and cancellation, typed events, report ordering and summaries, and stage adapters. Integration coverage exercises deterministic multi-host sequencing, cancellation from a stage event, discovery response handling, service/OS stage ordering, and a bounded **1,000-host × 100-port** offline workload. Unit coverage also exercises **10,000 same-deadline timers** and **10,000 pending correlations**. The port and service schedulers lazily sort terminal results when observed rather than sorting the complete result vector after every completion, preserving deterministic output while avoiding quadratic large-workload behavior. Linux raw transport tests skip cleanly when AF_PACKET capability is unavailable in the execution environment; they do not substitute a different transport or report fabricated network results.

The CLI retains the earlier `discover`, `interfaces`, and `os-detect` commands. The `scan` command now uses the unified orchestrator while preserving the prior Connect defaults and existing output formats. `--discovery --transport offline` intentionally reports nonresponsive discovery as `UNKNOWN` and therefore does not port-scan those hosts, because only discovered-UP hosts proceed to the next stage.

## Phase 12 — Target Resolution and Target Engine

Phase 12 replaces the Phase 11 CLI limitation of explicit resolved IPv4 hosts with a dedicated target subsystem. The boundary is `CLI input → TargetParser → TargetResolver → TargetNormalizer → TargetDeduplicator → deterministic TargetSet → ScanOrchestrator`. Discovery, port scanning, service detection, OS detection, and output receive only normalized `core::Host` values; they do not parse CIDR, ranges, hostnames, or comma-separated target text.

The target engine supports single IPv4 addresses, IPv4 CIDR, inclusive IPv4 ranges, hostnames resolved through the platform `getaddrinfo(AF_INET)` resolver, and comma-separated mixtures of these forms. CIDR expansion includes network and broadcast addresses exactly as requested, including `/32`, and does not silently remove addresses. Range expansion requires a valid non-reversed IPv4 interval. Hostnames must use DNS hostname syntax and only A records are requested; IPv6 is neither required nor claimed.

| Target form | Example | Result |
| --- | --- | --- |
| IPv4 | `127.0.0.1` | One normalized IPv4 address |
| CIDR | `192.168.1.0/30` | Four addresses, including `.0` and `.3` |
| Range | `192.168.1.10-192.168.1.20` | Eleven inclusive addresses |
| Hostname | `localhost` | One or more resolved IPv4 A records |
| Comma-separated | `192.168.1.1,192.168.1.0/30` | Collected, deduplicated, numerically sorted addresses |

Expansion is bounded by `--max-targets`, which defaults to `4096`, and hostname results are bounded by `--max-hostname-results`, which defaults to `64` per hostname. The engine checks expansion sizes before allocating or iterating huge CIDRs/ranges; `0.0.0.0/0 --max-targets 4096` returns `RESOURCE_EXHAUSTED` rather than truncating or attempting uncontrolled allocation. Duplicate addresses are collected through an efficient hash set and final targets are sorted by their numeric network-order `uint32_t` value, not lexical text order. Identical input therefore produces identical normalized ordering.

Target Engine errors are typed as `INVALID_TARGET`, `INVALID_IPV4`, `INVALID_CIDR`, `INVALID_RANGE`, `INVALID_HOSTNAME`, `RESOLUTION_FAILED`, `RESOURCE_EXHAUSTED`, `UNSUPPORTED_TARGET`, or `EMPTY_TARGET_SET`, with useful diagnostics. Synchronous hostname resolution is performed at the CLI/startup boundary before the scan enters the shared Phase 1 event loop; it is deliberately not called from an IOEngine callback, and the resolver interface is injectable so a future asynchronous implementation can replace it without changing the scanner.

The CLI examples are:

```sh
./bin/skan resolve 192.168.1.0/30
./bin/skan resolve 192.168.1.10-192.168.1.20 --max-targets 64
./bin/skan resolve localhost --json
./bin/skan resolve 0.0.0.0/0 --max-targets 4096
./bin/skan scan 192.168.1.0/30 --transport offline --method syn --tcp-ports 22,80
./bin/skan scan example.com --method connect --tcp-ports 443
```

`resolve` writes one normalized address per line by default or `{"targets":[{"address":"..."}]}` with `--json`; it never scans or opens a transport. A hostname resolution failure is distinct from malformed hostname syntax. The existing `scan 127.0.0.1`, transport, interface, method, port, service, OS, adaptive timing, output, and output-file behaviors remain unchanged except that `scan` now normalizes its target argument first.

## Network and safety boundary

Phase 4 implements IPv4 TCP Connect transport through nonblocking stream sockets, and Phase 5 adds TCP banner/probe service detection on OPEN results. Phase 9 adds explicit-interface Linux `AF_PACKET` byte transport and bounded capture as reusable infrastructure. Phase 10 connects that infrastructure to the existing TCP SYN and discovery scheduler seams without moving scan strategy into the transport. At the Phase 10 scope, these classes did not implement spoofing, ARP attack behavior, host-range expansion, public-target defaults, UDP scanning, alternate TCP flag scanning, evasion, live operating-system fingerprinting, Lua scripting, or dashboard functionality. Phase 6 provided packet-model-backed synthetic/injected OS evidence collection and deterministic matching; Phase 14 now adds the separate live-capable OS path documented below. Linux mode reports unavailable capabilities rather than fabricating success.

The default Phase 3 integration remains offline. Phase 4 and Phase 5 integration use only `127.0.0.1` and deliberately created local listening sockets; Phase 5 additionally verifies controlled SSH and HTTP banner responses. Phase 10 raw-packet integration uses only explicitly selected local interfaces and controlled local targets; capability-dependent tests skip cleanly when raw-socket privileges are unavailable. No public Internet targets were scanned.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.


## Phase 13 Bounded UDP Scanning

Phase 13 adds a first-class, opt-in UDP scan stage. Existing TCP, discovery, service-detection, OS-detection, target-normalization, timing, and output behavior remains unchanged unless `--udp` is supplied. The UDP stage executes after discovery and TCP scanning, when those stages are enabled, and before TCP-only service detection, OS detection, and output serialization. UDP results are never passed to the TCP service detector, and no service identity is inferred from a UDP port number.

The CLI requires an explicit transport for UDP scanning. The deterministic offline path is safe for tests and demonstrations, while the Linux path requires both `--transport linux` and an explicit `--interface`. Linux capability failures are reported; Skan never silently changes a requested Linux scan into an offline scan.

```sh
# Deterministic timeout classification with one UDP probe.
./bin/skan scan 192.0.2.10 --udp --transport offline \
  --udp-ports 53 --udp-timeout-ms 1500 --udp-retries 1 --output json

# Use the ten-port project-owned default UDP set.
./bin/skan scan 192.0.2.10 --udp --transport offline

# Explicit Linux raw UDP mode; requires AF_PACKET capture/injection capability.
./bin/skan scan 192.0.2.10 --udp --transport linux --interface eth0 \
  --udp-ports 53,123,161
```

`--udp-ports` accepts a single port, a comma-separated list, or an inclusive range. Values are restricted to `1..65535`, sorted, and deduplicated. The project-owned default set is `{53, 67, 68, 69, 123, 137, 161, 162, 500, 514}`. UDP uses a default maximum of 64 outstanding probes, a 1500 ms timeout, and one bounded retry. These values are independently configured from the unchanged TCP defaults.

| UDP evidence | Canonical state | Reason | Meaning |
| --- | --- | --- | --- |
| A validated UDP datagram from the target to the allocated source port | `OPEN` | `UDP_RESPONSE` | The target returned a correlated UDP response. |
| A validated ICMPv4 Destination Unreachable with code 3 and an embedded matching IPv4/UDP probe | `CLOSED` | `ICMP_PORT_UNREACHABLE` | The target explicitly reported that the destination UDP port is closed. |
| A validated administrative or network/host unreachable error with a matching embedded probe | `FILTERED` | `ICMP_ADMINISTRATIVELY_PROHIBITED` or `ICMP_NETWORK_UNREACHABLE` | The network supplied explicit filtering or reachability evidence. |
| No validated response after the bounded retry policy | `OPEN_OR_FILTERED` | `UDP_TIMEOUT` | UDP silence cannot distinguish an open service from filtering. |
| A correlated but malformed datagram/error or local transport failure | `ERROR` | Explicit malformed, socket, capability, or internal reason | The observation is not converted into a guessed port state. |

Each probe uses the existing Phase 2 `packet::UDP` and `packet::Packet` composition paths. The scheduler uses the shared Phase 1 reactor and Phase 7 timing controller; it does not create threads, sleeps, polling loops, blocking receive loops, or a second reactor. Source ports are allocated deterministically from a bounded ephemeral range, are unique among outstanding probes, and are released on response, timeout, retry, cancellation, and teardown. Correlation checks the logical probe identifier where available and the local/destination IPv4 addresses, source/destination ports, and UDP protocol fields. Unrelated, late, and duplicate observations cannot mutate completed results.

The runtime database `data/udp-probes.db` is Skan-owned and intentionally small. Its strict line-oriented records contain a unique probe name, destination port, protocol hint, maximum response size, and bounded hexadecimal payload. The current definitions cover minimal DNS, NTP, SNMP, NetBIOS, TFTP, IKE, and deterministic generic fallback probes. Malformed records, duplicate names or destination ports, invalid hexadecimal data, zero ports other than the single default record, and oversized payload/response limits are rejected. The database is not copied from or derived from Nmap data.

| Transport | UDP status | Network activity |
| --- | --- | --- |
| Offline recording transport | Implemented and deterministic | None; responses are injected by tests or callers. |
| Linux AF_PACKET transport | Implemented with capability gating | Sends Ethernet/IPv4/UDP frames and receives bounded Ethernet/IPv4/UDP/ICMP observations only when the selected interface and host policy permit it. |
| TCP Connect transport | Rejected for UDP | UDP is not silently reinterpreted as a TCP stream or normal-connect scan. |

UDP service identification and UDP OS fingerprinting are deliberately not implemented in this phase. IPv6, evasion, decoys, spoofing, fragmentation tricks, credentials, exploitation, Internet-wide scanning, and public-target traffic remain outside scope. UDP timeout is never reported as `CLOSED` or as `OPEN`; it is represented as `OPEN_OR_FILTERED` in every output format. JSON, XML, normal, and grepable writers preserve the UDP protocol, state, reason, probe name, retry count, and additive state counters.

## Phase 13 Architecture

The UDP execution path is:

```text
TargetEngine-normalized core::Target
                    ↓
             UdpScanStage
                    ↓
              UDPScheduler
          ↙                     ↘
RecordingUDPTransport     LinuxUDPScanTransport
          ↓                     ↓
  injected UDPResponse     LinuxTransport + LinuxCapture
                                ↓
                         PacketReceiver / ICMP parser
                    ↓
        shared IOEngine timers and event dispatch
                    ↓
        canonical PortResult and output report
```

The UDP transport is a sibling of the existing TCP raw adapter rather than a modification of TCP-specific submission or response contracts. It reuses the existing Linux transport, capture, packet receiver, interface selection, packet composition, and single-reactor lifecycle. Its protocol-specific correlation is kept in a bounded pending map keyed by the logical UDP probe identifier and verified against all wire-level correlation fields. The existing service stage receives only TCP `OPEN` results, and the OS stage filters merged results back to TCP before invoking the existing OS detector.

## Phase 14 — Live OS Fingerprinting Engine

Phase 14 completes the OS fingerprinting path without changing the existing discovery, TCP scan, service, target, timing, or output architecture. `OSDetectionStage` selects a deterministic recording transport for offline execution, an injected transport for tests and integrations, or `LinuxOSProbeTransport` only when the caller explicitly selects `--transport linux --interface <name>`. Each path uses the same `io::IOEngine`, bounded pending map, one-shot timers, packet models, response assessment, and matcher. The Linux adapter owns one raw transport and one capture descriptor, attaches capture to the existing reactor, and performs explicit teardown on every terminal and cancellation path.

The scheduler submits a bounded deterministic probe set for each resolved IPv4 host. The current families are TCP SYN, TCP ACK, TCP FIN, TCP NULL, TCP XMAS, closed-port TCP variants, ICMP Echo, UDP fingerprint, and UDP Port Unreachable probes. TCP probes vary flags and preserve IP characteristics; UDP probes use a project-owned payload and the existing `packet::UDP` and `packet::Packet` composition paths. The scheduler records generated, sent, response, timeout, unsupported, and malformed states, retries only according to the configured bounded timing profile, and never treats an absent response as an operating-system identity.

The runtime database is `data/os-fingerprints.db`. It is a small Skan-owned data file and is not imported from Nmap or another scanner. Its strict parser supports optional `Class` version/device fields, exact typed values, bounded inclusive numeric ranges, TCP option ordering, UDP payload length, UDP response behavior, response presence, duplicate signature rejection, duplicate fingerprint-name rejection, and malformed-value rejection. Matching uses only available evidence. TCP, ICMP, UDP, and correlated ICMP-error observations are retained in `OSDetectionResult`, together with confidence, match category, probe counters, timeout/malformed counters, and optional RTT. A missing response, unsupported probe, or unavailable capability is represented explicitly and does not become a guessed OS.

The live capture path validates both outer and embedded packet fields. TCP matching requires the target/local addresses, response ports, and acknowledgment relationship. UDP matching requires target/local addresses and reversed response ports. ICMP Destination Unreachable matching validates the ICMP checksum, type/code, quoted IPv4 header, quoted protocol, and quoted UDP or TCP fields required for correlation. Truncated, malformed, unrelated, duplicate, and late packets cannot complete or mutate another host’s pending work. Source addresses are obtained from the selected interface for live mode; offline tests retain deterministic source addresses.

| Mode | Behavior |
| --- | --- |
| Offline | Runs the complete bounded scheduler and matcher with no network descriptors. With no injected responses, the host receives explicit partial evidence and no fabricated identity. |
| Injected | Allows deterministic serialized TCP, UDP, ICMP, and ICMP-error responses for unit and integration tests. It is the preferred non-privileged validation seam. |
| Linux raw | Requires an explicit interface and AF_PACKET capture/injection capability. Permission, interface, capture, or send failures produce explicit unavailable evidence; there is no offline fallback. |
| Connect | Not used as a live OS transport. The OS stage reports capability-unavailable semantics rather than silently converting stream sockets into packet probes. |

The `os-detect` command accepts normalized IPv4 targets, IPv4 CIDRs and ranges through the Phase 12 target engine, `--os-db`, `--timeout-ms`, `--max-outstanding`, `--retries`, `--adaptive-timing`, `--transport offline|linux`, `--interface`, `--output`, `--output-file`, and `--json`. The default is deterministic offline mode. For live operation, selection is explicit:

```sh
./bin/skan os-detect 192.0.2.10 --transport linux --interface lo \
  --timeout-ms 500 --max-outstanding 8 --output json
```

Normal, JSON, XML, and grepable reports preserve OS state, error, confidence, probe counters, RTT, and TCP/ICMP/UDP evidence counts when available. Existing OS match records remain compatible. Phase 14 does not infer UDP service names from port numbers, does not run UDP service detection, does not add UDP-specific OS fingerprinting beyond the declared evidence probes, and does not implement IPv6, evasion, spoofing, decoys, credentials, exploitation, or public-target scanning. The test suite uses reserved documentation addresses, loopback capability checks, deterministic transports, and no public traffic.

## Phase 14 verification scope

The Phase 14 tests cover strict OS database parsing, optional metadata, ranges, UDP signatures, all probe families, packet-backed TCP/UDP/ICMP assessment, malformed and unrelated evidence, scheduler retries/timeouts/cancellation, injected multi-host completion, a 1,000-host/12,000-probe offline stress case, structured output fields, CLI validation, and explicit Linux capability skips. Sanitizer, coverage, fuzz, debug, release, and clean production builds use the same source and test registration paths as earlier phases.

## Post-Phase-14 deep audit

The post-Phase-14 audit, scoped Nmap capability comparison, benchmark methodology/results, repaired defects, and remaining limitations are documented in [`AUDIT_REPORT.md`](AUDIT_REPORT.md). Reproduce the offline measurements with the opt-in `make benchmark` target; the detailed results and raw CSV are in [`BENCHMARKS.md`](BENCHMARKS.md) and [`benchmarks/results_2026-08-25.csv`](benchmarks/results_2026-08-25.csv). The Phase 16 implementation, validation gates, and remaining capability boundaries are recorded in [`AUDIT_REPORT.md`](AUDIT_REPORT.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`BENCHMARKS.md`](BENCHMARKS.md), and [`NEXT_PHASE_ROADMAP.md`](NEXT_PHASE_ROADMAP.md).


## Phase 15 — IPv6 Foundation and Dual-Stack Extension

Phase 15 extends the existing architecture from IPv4-only identity to a typed dual-stack boundary. `core::IpAddress` stores family and binary address bytes; canonical text is rendered only at presentation boundaries. Equality, hashing, deduplication, correlation, and deterministic ordering therefore distinguish IPv4 and IPv6 without relying on textual spelling. `core::Host`, `target::ResolvedTarget`, discovery submissions, port submissions, service submissions, and report hosts carry the typed identity while retaining safe compatibility fallbacks for legacy aggregate callers.

The Target Engine accepts IPv4 and IPv6 literals, IPv4 and IPv6 CIDR notation, inclusive ranges, comma-separated mixtures, and synchronous `getaddrinfo(AF_UNSPEC)` hostname resolution. A and AAAA results are bounded by `--max-hostname-results`; CIDR and range expansion is checked against `--max-targets` before iteration or allocation. IPv6 expansion is deliberately bounded and never attempts an uncontrolled `/0` materialization. Normalized results are deduplicated by binary identity and sorted deterministically by family and address bytes.

The packet layer remains one shared composition path. It now supports a strict 40-byte IPv6 base header, traffic class and flow label fields, payload-length bounds, IPv6 pseudo-header checksums for TCP and UDP, and a separate ICMPv6 model. The bounded extension parser recognizes Hop-by-Hop Options, Routing, Fragment, and Destination Options headers and reports malformed, unsupported, and budget-exceeded states distinctly. It does not implement fragmentation generation, evasion, spoofing, or extension-header attack behavior. ICMPv6 support includes Echo Request/Reply, bounded Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, and limited Neighbor Discovery message recognition; it is not a complete ND stack.

`PacketReceiver` recognizes Ethernet EtherType `0x86DD`, parses the IPv6 base header and bounded extension chain through the shared packet parser, then exposes typed IPv6/TCP/UDP/ICMPv6 observations. Packet filtering and correlation include binary family-aware address identity, so an IPv4 observation cannot satisfy an IPv6 pending probe. Existing IPv4 bounds, UDP length slicing, malformed-frame handling, and shutdown-safe capture teardown remain unchanged.

The normal nonblocking TCP Connect transport uses the same `IOEngine`, event objects, timers, and connection lifecycle for AF_INET and AF_INET6. Controlled loopback tests exercise `::1` when the platform provides it. Service detection uses that same AF_INET6 stream path for bounded TCP probes and does not infer service identity from address or port alone. Offline discovery and UDP scanning can construct and correlate IPv6 packets through the existing schedulers and recording seams. UDP timeout remains `OPEN_OR_FILTERED`; ICMPv6 unreachable evidence maps only to the existing explicit closed/filtered classifications and never becomes a guessed open result.

The Phase 15 historical boundary did not claim native raw IPv6. Phase 17 adds typed IPv6 branches to the existing Linux discovery, raw SYN, raw UDP, and OS adapters, while retaining explicit capability/routing failure whenever a non-loopback destination MAC or complete neighbor path is unavailable. IPv6 OS fingerprinting now accepts only reliable typed packet evidence and never derives identity from address, service, or port. This boundary is intentional and keeps capability reporting honest.

Every canonical host result includes `family` with the value `ipv4` or `ipv6`. JSON and XML always serialize it; grepable output includes a terminal-safe `family=` field; normal output visibly labels IPv6 hosts while preserving the established IPv4 line form. The `resolve` command emits the family in JSON, and `scan`, `discover`, and `os-detect` accept typed IPv6 targets. For example:

```sh
./bin/skan resolve '127.0.0.1,::1' --json
./bin/skan discover ::1 --transport offline --icmp --timeout-ms 10
./bin/skan scan '127.0.0.1,::1' --method connect --tcp-ports 1 --output json
./bin/skan scan ::1 --udp --transport offline --udp-ports 53 --output grepable
```

Phase 15 tests cover canonical typed addresses, IPv6 literals/CIDR/ranges, mixed targets, A+AAAA resolver seams, bounded expansion, IPv6 base-header golden vectors, extension budgets and malformed chains, TCP/UDP/ICMPv6 checksum paths, PacketReceiver EtherType and truncation handling, family-aware correlation, AF_INET6 loopback Connect/service behavior, deterministic offline UDP/discovery construction, 10,000-scale bounded workloads, fuzz entry points, and capability-dependent raw-socket skips. All tests are local or synthetic; no public-target traffic is generated.

## Phase 15 architecture boundary

```text
TargetParser / AF_UNSPEC resolver
              ↓
Typed TargetSet (family + binary address)
              ↓
Existing ScanOrchestrator and one ScanPipeline
              ↓
Existing schedulers and shared IOEngine/timers
       ↙              ↓                ↘
AF_INET/AF_INET6   shared Packet      explicit Linux raw
Connect/service    IPv4/IPv6 model   IPv6 unavailable boundary
       ↓              ↓
Canonical family-aware ScanReport and writers
```

Phase 16 completes the production-safe dual-stack boundary described below. Native Linux raw IPv6 discovery/scanning, complete Neighbor Discovery, IPv6 OS fingerprinting, evasion, spoofing, fragmentation attacks, exploitation, credential handling, persistence, and public-target scanning remain explicitly outside the capability boundary.

## Phase 15 audit note

The Phase 15 implementation reuses the single reactor, existing timers, packet composition, capture/receiver, schedulers, transports, Target Engine, orchestrator, report model, and output writers. It adds no worker threads, polling loops, sleeps, second reactor, duplicate packet stack, implicit raw interface selection, fallback path, or public-target traffic.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.


## Phase 16 — Production Dual-Stack IPv6 Completion

Phase 16 hardens the typed dual-stack boundary without introducing another scanner, scheduler, packet stack, reactor, thread, polling loop, sleep, fallback, or implicit interface choice. `core::parse_ip_address` is the shared strict parser for IPv4 and IPv6 literals. IPv6 zones use one validated `%zone` token, preserve the zone in canonical text and binary identity, and resolve only the explicitly supplied numeric interface index or interface name. Link-local live behavior never selects an interface implicitly. Target expansion and hostname A/AAAA results are bounded by hard ceilings of 1,000,000 targets and 4,096 hostname results in addition to caller-selected lower limits.

The shared packet layer now provides a bounded quoted IPv6/UDP extractor for ICMPv6 errors. It validates the quoted base header, supported extension chain, fragmentation constraints, transport header length, and UDP identity before the existing UDP scheduler correlation map can classify a response. ICMPv6 Destination Unreachable code 4 is classified as UDP closed; unsupported or malformed quotes remain non-conclusive. PacketReceiver validates IPv4 and IPv6 TCP/UDP checksums, accepts the standards-defined zero IPv4 UDP checksum, rejects a zero IPv6 UDP checksum, and continues to validate ICMPv6 checksums and all existing length/extension budgets.

AF_INET6 TCP Connect, service detection, offline discovery, offline UDP, typed SYN construction, scoped target propagation, mixed-family orchestration, family-aware output, fuzz entry points, and deterministic 10,000-host IPv6/mixed scheduler workloads are integrated through the existing contracts. `skan interfaces` reports typed IPv6 addresses, link-local zones, and separate family capability fields. Local `::1` service tests cover HTTP-like and SSH-like banners when IPv6 loopback is available. The benchmark includes IPv6 target expansion, IPv6 receiver parsing, and mixed-family UDP scheduler rows.

Native Linux raw IPv6 discovery, raw IPv6 TCP SYN transmission, raw IPv6 UDP transmission, complete Neighbor Discovery, and IPv6 OS fingerprinting remain explicitly unavailable. The current Linux raw adapters require an explicit interface and retain their tested IPv4/ARP capability boundary; an IPv6 request fails with a capability result and never falls back to Connect or offline mode. The sandbox’s AF_PACKET tests are expected to skip when the host denies `Operation not permitted`. These limitations are deliberate: Skan reports only evidence and capabilities that the selected transport can actually provide.

Scoped and mixed-family examples are:

```sh
./bin/skan resolve 'fe80::1%lo,127.0.0.1' --json
./bin/skan scan '127.0.0.1,::1' --method connect --tcp-ports 1 --output json
./bin/skan scan 'fe80::1%lo' --method connect --tcp-ports 80 --output json
./bin/skan interfaces --json
```

All Phase 16 test and benchmark inputs are local, documentation-space, synthetic, or injected. No public-target traffic, evasion, spoofing, exploitation, credential handling, persistence, or stealth mechanism is introduced.

## Phase 16 audit note

The Phase 16 implementation preserves the single `io::IOEngine` and existing timer lifecycle across discovery, TCP/UDP scanning, service detection, OS detection, capture, orchestration, and output. The retained [`POST_PHASE15_AUDIT.md`](POST_PHASE15_AUDIT.md) records the pre-Phase-16 findings and their resolution status; it is historical audit evidence, not a second implementation boundary.

## Phase 17 IPv6 completion

Phase 17 extends the existing single-reactor architecture with native IPv6 branches in the Linux discovery, TCP SYN, UDP, and OS-probe adapters. These adapters reuse the shared packet model, PacketReceiver, pending-correlation maps, schedulers, and IOEngine; they do not create alternate scanners, reactors, threads, polling loops, or Connect fallbacks. IPv6 OS evidence is typed at submission and response boundaries and is accepted only after exact source, destination, port, sequence, and ICMPv6 identity checks.

Link-local targets require an explicit `%zone` and an explicitly selected interface. Named and numeric zones are resolved and compared against that interface; the program never chooses an interface implicitly. Interface output reports typed IPv6 addresses and family-specific AF_INET6, routing, CAP_NET_RAW, capture, and injection facts. Native non-loopback Ethernet IPv6 transmit remains unavailable when an explicit destination MAC or complete neighbor-resolution path is absent, and the CLI reports that boundary instead of silently falling back.

ICMPv6 Neighbor Solicitation and Advertisement parsing is bounded and validates target addresses and option lengths, including Source/Target Link-Layer Address options. Complete asynchronous Neighbor Discovery state and automatic neighbor resolution remain deferred unless an explicit interface-local state machine can be enabled safely. No public-target traffic, spoofing, evasion, exploitation, credentials, persistence, or stealth behavior is part of this implementation.

Phase 17 validation includes deterministic IPv6 OS-probe and Neighbor Discovery packet vectors, raw-transport capability skips when AF_PACKET is unavailable, full scheduler/orchestrator regression coverage, sanitizers, coverage, fuzz/benchmark gates, and output/CLI capability checks. OS observations carry an explicit address-family tag; mixed-family aggregates are rejected and the current built-in fingerprint database remains IPv4-only, so IPv6 evidence produces no compatible fingerprint rather than a false positive. The current raw IPv6 boundary is capability-honest: non-loopback Ethernet transmission requires a configured neighbor path, and no implicit Neighbor Discovery state machine is claimed.

## Phase 18 production IPv6 OS fingerprinting
Phase 18 adds a project-owned IPv6 fingerprint database at `data/os-fingerprints-v6.db` and combines it with the existing IPv4 database through the existing bounded database loader. Each record has explicit `ADDRESS_FAMILY`, stable `ID`, specificity, and typed signatures. The parser enforces family metadata for IPv6 records, duplicate record names and IDs, record/signature/string/line/file limits, and deterministic parse failures; explicit database paths remain supported.

OS evidence now carries both an address-family tag and an explicit protocol tag (`TCP`, `UDP`, `ICMPv4`, or `ICMPv6`). The matcher filters by family before scoring and rejects unknown or mixed-family aggregates. Match ordering is deterministic by confidence, specificity, display name, and stable fingerprint ID. IPv6 TCP, UDP, and ICMPv6 probes are built and assessed through the existing probe, scheduler, capture, correlation, and orchestrator contracts. No identity is inferred from an address, port, service label, local platform, or guessed behavior.

Normal, JSON, XML, and grepable output now expose the OS address family and selected fingerprint ID. Mixed-family offline scheduler and orchestrator paths remain safe: they execute through the existing single pipeline, preserve family ambiguity as `Unknown`, and do not permit an IPv4 record to match IPv6 evidence. Fuzz and offline benchmark harnesses exercise the IPv6 parser, matcher, probe construction, NDP accessors, receiver, and mixed-family scheduling without network activity.

Live raw IPv6 OS probing remains capability-dependent. The Linux adapter requires an explicitly selected interface, usable AF_PACKET capture/injection, a valid typed source address, and either an explicitly supplied destination MAC or a supported interface-local neighbor path. The sandbox reports `Operation not permitted` when AF_PACKET is unavailable; it does not fall back to Connect, IPv4, offline, or implicit-interface behavior. The built-in IPv6 records are generic project-owned laboratory signatures and are not authoritative vendor identification.

Phase 18 continues to exclude public-target traffic, evasion, spoofing, poisoning, fragmentation attacks, exploitation, credentials, persistence, stealth, worker threads, polling loops, and duplicate pipeline or scheduler architectures.
## Phase 18 audit note
The Phase 18 changes preserve the single `io::IOEngine` reactor and the existing Target Engine → Scan Orchestrator → Discovery → Port Scan → Service → OS → Output pipeline. The principal new boundary is typed data: IPv6 records and observations cannot cross the family filter into IPv4 matching, and every selected result reports its family and stable fingerprint ID. The raw Linux capability result is derived from an actual AF_PACKET probe and remains an environmental capability fact, not a claim that every host can transmit IPv6 packets.

## Phase 19 Production Network Capability Completion

Phase 19 hardens and validates the existing dual-stack stack without adding another pipeline. The established Target Engine → Scan Orchestrator → Discovery → Port Scan → Service → OS → Output flow continues to use one `io::IOEngine`, the shared packet model, Linux transport/capture, `PacketReceiver`, correlation tables, adaptive timing, and existing writers.

The interface inventory now exposes typed per-capability facts for IPv4 and IPv6. Each fact is `AVAILABLE`, `UNAVAILABLE`, or `UNKNOWN` and includes the selected interface, address family, reason, and optional diagnostic. The facts are evidence-backed: AF_INET/AF_INET6 socket probes, route-table presence, assigned source addresses, and AF_PACKET interface bind are distinguished. Derived raw SYN, UDP, ICMP/ICMPv6, and link-local NDP capabilities are not reported as available when their prerequisites are absent. Legacy boolean fields remain for compatibility, while `interfaces --json` exposes the typed `capabilities.ipv4` and `capabilities.ipv6` objects.

Explicit Linux IPv6 discovery now reaches the existing Linux adapter after strict interface and zone validation. The adapter performs bounded local-link Neighbor Solicitation/Advertisement processing, validates target/source/option/MAC identity, uses solicited-node multicast mapping, maintains a maximum 64-entry 30-second interface-local cache, expires stale entries, and evicts deterministically. Missing AF_PACKET permission, invalid source selection, missing route, or unresolved destination MAC remains a non-zero capability failure; Skan does not downgrade Linux to Connect or offline mode and does not use ARP for IPv6.

The raw IPv6 SYN, UDP, ICMPv6 discovery, service, and OS paths retain exact family-aware addresses, ports, identifiers, sequence/acknowledgement checks, checksums, deadlines, duplicate/late handling, and existing cancellation ownership. Loopback and private lab fixtures are the only live-test scope. The restricted execution environment reports `UNAVAILABLE` with `Operation not permitted` for AF_PACKET-dependent operations; this is an environmental capability result, not a fabricated live success.

Phase 19 validation includes IPv4, IPv6, and mixed offline resolution/scans, controlled local IPv6 service coverage where platform support exists, typed capability tests, NDP vectors, malformed/truncated packet tests, correlation and timer stress, sanitizer gates, offline benchmarks, fuzz-harness compile checks, and structured output validation. The full capability matrix is recorded in `AUDIT_REPORT.md`. No unrestricted claim of full IPv6 support is made.


## Phase 20 Production-Grade Scan Engine Hardening

Phase 20 hardens the existing single-pipeline implementation rather than introducing a replacement architecture. The execution path remains Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output, with one thread-affine epoll `IOEngine`, one timer abstraction, shared packet models, bounded queues, and explicit transport selection.

`ScanMetrics` now exposes low-cost counters for targets, probes, retries, bytes, parser/correlation outcomes, active and peak probes, stage-duration slots, RTT, timeout, cancellation, and drop-rate state. The generic `ScanGroup` lifecycle updates submission, completion, timeout, failure, active-probe, peak-probe, and retry values at the existing state-transition points. No worker thread, polling loop, sleep, or asynchronous task system was added.

The reusable `CorrelationTable` retains exact typed keys and O(1)-average unordered lookup while adding deadline indexing for deterministic expiry cleanup. Duplicate, found, missed, late, explicit removal, and expiry-cleanup counts are observable. Insertion rolls back if the expiry index cannot be allocated. The orchestrator now reserves known cardinalities, deduplicates aggregate hosts through non-owning `string_view` keys, and selects per-host OS ranges with binary-search boundaries rather than rescanning all results for every host.

Service detection now has an original bounded corpus covering additional TCP banners, TLS record-header/alert identification, and UDP DNS, NTP, SNMP, and SSDP-style probes. The database grammar supports TCP/UDP declarations and exact, prefix, substring, and regex rules with deterministic priority; anchored capture rules remain available for structured product/version extraction. UDP service scheduling is protocol-aware and separated from TCP matching. Offline recording covers both protocols, while live datagram transport uses bounded nonblocking sockets through the same IOEngine and router. TLS handling is identification-only and does not perform certificate attacks, downgrade attempts, credentials, brute force, or exploitation.

Output writers now sort non-owning pointer views instead of copying complete port, service, and OS result objects for every host. JSON, XML, normal, and grepable formats retain deterministic ordering and escaping. Phase 20 adds 10,000-host output regression coverage and benchmark rows for all four formats.

The fuzz harness now exercises service matching and output escaping in addition to the packet, quoted-packet, target, timing, UDP, and OS paths. The corpus contains truncated, zero-length, malformed-length, malformed-option, malformed-extension, nested-quote, and invalid-target seeds. Resource and capability boundaries remain explicit: if AF_PACKET is unavailable, Linux tests and commands report capability failure or a clean skip and never replace live raw execution with Connect or offline execution while claiming live validation.

Phase 20 validation is restricted to offline fixtures, loopback, and private laboratory-safe paths. In the current sandbox, AF_PACKET opens fail with `Operation not permitted`, so raw SYN, raw UDP, raw OS, and Linux discovery are capability-dependent rather than live-validated. Non-loopback raw probes still require the existing explicit neighbor/MAC context where applicable. Skan remains a bounded practical subset and is not Nmap-equivalent; it does not copy Nmap source code, databases, or NSE scripts.

## Phase 21 Status Override — Live-Network Hardening

Phase 21 extends the existing single Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline and shared epoll `IOEngine`; no second reactor, worker-thread model, polling loop, sleep-based timing path, fallback transport, or alternate output tree was introduced.

The interface capability model now includes typed preflight categories (`READY`, `INVALID_INTERFACE`, `INTERFACE_DOWN`, `NO_SOURCE_ADDRESS`, `NO_ROUTE`, `CAPABILITY_UNAVAILABLE`, `CAPTURE_UNAVAILABLE`, `INJECTION_UNAVAILABLE`, `UNSUPPORTED_FAMILY`, and `MTU_UNAVAILABLE`). Enumeration reports interface MTU, default-route evidence, Ethernet capture/injection facts, address family, source, route, and raw capability diagnostics. `preflight_interface()` is bounded, explicit-interface-only, non-transmitting, and family-aware. Linux discovery receives an explicit target-family hint so IPv6 diagnostics do not collapse into IPv4 wording. Raw TCP SYN, UDP, discovery, and OS adapters perform startup and target-family preflight and never fall back to Connect or offline mode.

Phase 21 completes the public metrics contract for target failures, cancellations, retries, SRTT, RTTVAR, RTO, and timeout backoffs. Counter increments are saturating-safe; RTT state is updated only by valid RTT samples. JSON, XML, normal, and grepable outputs expose the new metric fields and preserve deterministic ordering. XML carries OS matched/mismatched/unavailable evidence fields; normal and grepable formats expose service method/probe/error/RTT and OS fingerprint identity where available.

Validation remains capability-honest. The full offline regression suite, output writers, metrics tests, benchmark workloads, CLI parsing, and local Connect paths are exercised in the sandbox. AF_PACKET-dependent raw tests are skipped with the exact kernel diagnostic `Operation not permitted`; the sandbox therefore does not claim live raw SYN, raw UDP, ICMP/ICMPv6, NDP, or raw OS validation. A requested Linux operation exits nonzero with a structured stderr diagnostic such as `category=CAPTURE_UNAVAILABLE family=ipv6`; no alternate transport is selected. Only loopback, controlled local, offline, and private/documentation-address fixtures are permitted.

Nmap comparison remains intentionally non-equivalent: Skan has a smaller project-owned service and OS corpus, bounded identification-only TLS handling, no NSE/CPE breadth, and no evasion, spoofing, exploitation, credential, persistence, or public-target capability.


## Phase 22 Status Override

Phase 22 hardens the production live-path boundary without creating a second pipeline or reactor. The existing interface module now provides deterministic target-aware raw-interface selection from operational source and route evidence when `--interface` is omitted. Explicit interfaces remain honored, scoped IPv6 zones are validated against the selected interface, and mixed-family targets require one interface that satisfies every family rather than silently splitting or falling back.

Linux discovery now patches ARP requests with the selected interface MAC and IPv4 source address and validates Ethernet destination, Ethernet sender, ARP sender identity, target MAC, target IPv4, and operation before accepting a reply. TCP Connect now preserves routed-unreachable and local-source-address failures as distinct `UNREACHABLE`/`UNKNOWN` results with structured reasons. Raw UDP records target-family preflight, source-selection, frame-construction, and injection diagnostics in the shared transport session. Raw OS capability failures now terminate the live stage explicitly instead of returning success with an unavailable result.

Phase 22 validation covers these changes with unit, integration, offline, and controlled loopback tests. The sandbox continues to deny AF_PACKET with `Operation not permitted`; therefore raw SYN, ARP, NDP, raw UDP, ICMP/ICMPv6, and raw OS exchange remain capability-dependent and are never reported as live success. No public target was contacted. The project remains intentionally smaller than Nmap and does not include copied Nmap code, databases, NSE, evasion, spoofing, exploitation, credential handling, or persistence.

| Phase | Current status |
| --- | --- |
| Phase 22 — production live-interface selection, ARP identity hardening, structured unreachable/error semantics, and capability-honest raw OS failure | Complete; committed and pushed after final verification |
| Phase 22 — restricted-sandbox raw capability | Unavailable: AF_PACKET returns `Operation not permitted` |


## Phase 23 Status Override

Phase 23 extends the same production pipeline with typed discovery `UNREACHABLE` evidence, exact quoted IPv4/IPv6 ICMP unreachable correlation for live TCP SYN and discovery probes, canonical host-unreachable output counts, and strict `-p`/`-p-` TCP selection compatibility. The implementation retains one epoll reactor, existing timers, schedulers, packet models, capture path, correlation tables, adaptive timing, and `ScanReport` output model.

The repository contains no authorization gate, mandatory loopback policy, private-range rejection, or hidden target allowlist. User-supplied syntactically valid IPv4/IPv6 targets continue through the existing target and capability checks. Raw Linux behavior remains capability-honest: the current sandbox reports AF_PACKET `Operation not permitted`, so raw exchange is not claimed as live-validated and no transport fallback is used.


## Phase 24 Status

Phase 24 hardens the already-existing live path rather than adding a new scanner architecture. Linux TCP SYN frame composition now recalculates the TCP pseudo-header checksum from the selected IPv4 or IPv6 source and destination addresses before transmission. The existing typed discovery and SYN response paths retain exact quoted-packet correlation, explicit unreachable evidence, deterministic source/interface selection, bounded timers, and canonical output.

The Phase 23 baseline contains no artificial authorization gate, mandatory loopback restriction, private-range allowlist, or hidden target policy. Operator-supplied targets remain subject to the existing syntax, resource, route, family, and capability checks. TCP Connect loopback validation is available in this environment for IPv4 and conditionally IPv6; raw Linux SYN, UDP, ARP, NDP, ICMP/ICMPv6, capture, service-over-raw, and raw OS exchanges remain capability-dependent because AF_PACKET returns `Operation not permitted` in the sandbox. No live raw success is claimed.

The Phase 24 validation record separates implemented, offline-tested, loopback-tested, capability-dependent, and unavailable behavior. No public or arbitrary external target was contacted.


## Phase 25 Status — Production Live Remote Network Scanning

Phase 25 extends the existing scanner toward explicitly selected remote IPv4 and IPv6 targets without adding a second pipeline, scheduler, reactor, packet framework, or output model. The CLI now accepts `--transport connect`, `--transport offline`, and `--transport linux` explicitly; Connect remains the normal nonblocking socket path, offline remains the recording/injected path, and Linux remains capability-gated raw packet mode. No transport is selected implicitly as a substitute for another.

The Linux SYN path uses the selected source address, deterministic source port and sequence identity, family-correct Ethernet/IP/TCP frame construction, IPv4 and IPv6 pseudo-header checksums, exact response correlation, and typed ICMP unreachable handling. Existing deterministic automatic interface derivation and authoritative `--interface` selection remain active. ARP and bounded NDP behavior remain strict and capability-dependent for remote Ethernet paths.

Remote target specifications remain bounded through the existing Target Engine and include IPv4/IPv6 literals, CIDR, ranges, hostnames, and mixed target sets. In this environment real loopback Connect validation passes for IPv4 and IPv6. Raw remote IPv4/IPv6, UDP, discovery, ARP, NDP, service-over-raw, and OS-over-raw exchange is implemented but not live-validated because AF_PACKET returns `Operation not permitted`. No public target was contacted and no unsupported capability is represented as live success.
