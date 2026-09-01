# Skan Architecture

Skan is an original Linux network-scanning platform designed as a modular C++20 application. The architecture is influenced by general scanner engineering principles, but all Skan implementations are original and the project does not claim compatibility with any other scanner.

## High-level stack

```text
Skan
│
├── Core
├── I/O Engine
├── Packet Layer
├── Host Discovery
├── Scan Engine
├── Port Scanning
├── Detection
├── Data Layer
├── Lua Scripting
├── Output
├── Network Transport and Packet Capture
├── Evasion
├── CLI
└── Dashboard
```

The implemented dependency direction is deliberately narrow:

```text
Core
  ↓
Packet Layer
  ↓
Target Resolver
  ↓
Host Discovery
  ↓
Port Scan Scheduler and transports
  ↓
Service Detection
  ↓
OS Fingerprinting Architecture
  ↓
Output
  ↓
Network Transport and Packet Capture (infrastructure boundary)
```

## Runtime resources and installation boundary

`core::RuntimePaths` is the single resource-location boundary for the service, UDP, and IPv4/IPv6 OS fingerprint databases. Resolution is deterministic: explicit CLI overrides win; an installed executable uses resources relative to its executable prefix; a development executable may use the adjacent source-tree data directory; and the compile-time FHS data directory is the final configured candidate. The current working directory is never a resource root.

Production installation places the executable in `/usr/bin/skan` and immutable project-owned databases in `/usr/share/skan`. `DESTDIR` affects staging only and is never compiled into the binary. Missing database sets fail visibly, and the IPv4/IPv6 OS database pair is selected atomically so evidence cannot be mixed across installations.

The Phase 1 I/O Engine is independent infrastructure. Phases 3–6 use it through its public event-loop and timer API; they do not duplicate the reactor or create a second event loop.

## Language responsibilities

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Core, I/O engine, packet representation, discovery, orchestration, detection, data, output, networking, target resolution, and CLI | Phase 0–15 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented phases

**Phase 0 — Foundation** provides C++20 core types, constants, strongly typed status handling, timestamped logging, the CLI bootstrap, the minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** provides a Linux-first `epoll` reactor, logical event registration and lifecycle management, bounded and continuous run modes, monotonic one-shot timers, cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup.

**Phase 2/15 — Packet Layer** provides offline packet representation, composition, validation, deterministic serialization, lightweight parsing, and checksums for Ethernet II, IPv4/IPv6, TCP, UDP, ICMPv4, ICMPv6, and bounded IPv6 extension chains.

**Phase 3 — Host Discovery** provides a bounded scheduler, common probe abstraction, ICMP Echo correlation, TCP SYN/ACK and RST evidence classification, minimal ARP request/reply representation, monotonic timeouts, RTT calculation, duplicate and late response handling, deterministic host-state aggregation, and a safe recording transport for offline tests.

**Phase 4/15 — Scoped TCP Port Scan** provides TCP-only port selection and results, a bounded scheduler over the Phase 1 reactor, real nonblocking AF_INET/AF_INET6 TCP Connect transport, and an offline packet-model-backed TCP SYN probe. Phase 10 adds the explicit-interface Linux SYN adapter without changing this scheduler contract.

**Phase 5/15 — Service Detection** provides an opt-in, TCP-only detector that consumes OPEN Phase 4 results, performs bounded nonblocking AF_INET/AF_INET6 banner/probe exchanges through the same reactor, matches responses against a compact project-owned database, and emits deterministic structured `ServiceResult` values. It is complete for this bounded scope; Phase 5 itself does not implement UDP detection, credential handling, or service exploitation. Live OS fingerprinting is provided separately by the Phase 14 path.

**Phase 6 — OS Fingerprinting Architecture** provides typed packet evidence extraction, a small Skan-owned runtime fingerprint database, deterministic weighted available-evidence matching, and a bounded `OSScheduler`/`OSDetector` over the shared Phase 1 reactor. Phase 14 extends this architecture with TCP SYN/ACK/FIN/NULL/XMAS and UDP/ICMP evidence families plus explicit live transport capability handling.

**Phase 7 — Adaptive Timing + Scan Engine** is complete for the reusable offline and opt-in scheduler scope described below.

**Phase 8 — Output + Result Serialization** is complete for the pure presentation scope described below.

**Phase 9 — Network Transport + Packet Capture** is complete for the infrastructure-only scope described below. It supplies explicit-interface Linux byte transport and bounded capture, deterministic offline seams, layered packet observation, small filtering, and a reusable correlation boundary. It does not add a scanner or traffic-evasion mechanism.

**Phase 10 — Real Network Scan Integration** is complete for the explicit Linux TCP SYN and discovery adapter scope described below. It preserves offline mode, uses one IOEngine, feeds existing scheduler callbacks, and provides the raw transport/capture lifecycle reused by the Phase 14 Linux OS adapter.

**Phase 11 — Unified Scan Orchestrator** is complete for sequential discovery, port, service, OS, and output coordination over the existing bounded asynchronous subsystems, with cancellation, typed events, deterministic offline transports, and capability-honest Linux behavior.

**Phase 12/15 — Target Resolution and Target Engine** is complete for typed IPv4/IPv6 literals, CIDR, inclusive ranges, hostnames through bounded synchronous A+AAAA resolution, mixed input, binary-identity deduplication, deterministic family-aware ordering, and normalized handoff to Phase 11. Resolution occurs before the scan reactor and never blocks an IOEngine callback.

**Phase 13/15 — Bounded UDP Scan Engine** is complete for explicit offline UDP scanning and capability-gated Linux AF_PACKET UDP transport. It adds strict project-owned UDP probes, bounded source-port allocation, IPv4/IPv6 offline packet construction, explicit unreachable classifications, retries and timeout semantics, pipeline/output integration, stress tests, and no implicit fallback. Linux raw IPv6 UDP and UDP OS fingerprinting remain unavailable.

## Target integration

Phase 12/15 owns target selection parsing and normalization before the existing `core::Target` boundary. Discovery, port scanning, service detection, and OS detection receive normalized `core::Host` values with typed binary family identity; none of those modules understands CIDR, ranges, hostnames, or comma-separated input. The scan pipeline performs normal address, port, protocol, transport, and resource validation after Target Engine resolution; it does not add a hidden public-target default.

## Discovery architecture

The execution model is:

```text
core::Target (already resolved and validated)
          ↓
DiscoveryScheduler
          ↓
bounded work queue
          ↓
DiscoveryProbe::build()
          ↓
Phase 2 packet serialization
          ↓
DiscoveryTransport::submit()
          ↓
Phase 1 IOEngine timers/event loop
          ↓
Discovery::receive()
          ↓
probe-local response assessment
          ↓
DiscoveryResult evidence
          ↓
HostState aggregation
```

`DiscoveryScheduler` owns probe implementations through `std::unique_ptr`, borrows the shared `IOEngine` and caller-owned transport, and stores pending correlation entries in a bounded map. It is single-thread-affine like the Phase 1 engine. There is no thread-per-host model, worker pool, blocking sleep, or independent reactor.

The `DiscoveryProbe` abstraction has three responsibilities: identify its strongly typed probe type, build one correlated submission using the Phase 2 packet API, and assess a received response as `Matching`, `Unrelated`, or `Malformed`. Transport delivery is separate from packet construction, allowing deterministic offline tests and preventing a hidden network path inside serialization code.

## Probe types

| Probe | Packet and correlation behavior | Evidence |
| --- | --- | --- |
| ICMP Echo | Uses Phase 2 `ICMP` or `ICMPv6` Echo Request serialization. Correlation requires typed target identity, Echo Reply type/code, deterministic identifier, and sequence. | Matching Echo Reply produces `UP` with `ICMP_ECHO_REPLY`. |
| TCP | Uses Phase 2 `TCP` serialization for exactly one configured port. Correlation requires the target source address, response source/destination ports, and SYN sequence acknowledgment when applicable. | SYN/ACK produces `UP` with `TCP_SYN_ACK`; RST produces `UP` with `TCP_RST`. A timeout is `UNKNOWN`. |
| ARP | Uses a discovery-local 28-byte Ethernet/IPv4 ARP representation. Requests and replies are bounds-checked and correlate target IPv4, operation, and sender/target IPv4 fields. | Matching ARP reply produces `UP` with `ARP_REPLY`. |

The default TCP discovery port is centralized as `kDefaultTcpDiscoveryPort` and is **80**. A caller may select one explicit port, but the scheduler never enumerates ports and Phase 3 does not implement a TCP scanner.

ARP remains an offline representation in this phase. A future lab transport may connect it to a directly reachable Ethernet interface; ARP spoofing, poisoning, gratuitous ARP attacks, and any other offensive ARP behavior are outside the architecture.

## Port-scan architecture

The Phase 4 execution model is:

```text
core::Target (already resolved and validated)
          ↓
PortScanScheduler
          ↓
bounded host × TCP-port queue
          ↓
TcpConnectProbe or TcpSynProbe
          ↓
PortScanTransport
       ↙                  ↘
TcpConnectTransport       RecordingPortScanTransport / injected SYN transport
       ↓
Phase 1 IOEngine events and timers
          ↓
PortResult (target, TCP port, state, probe, reason, optional RTT)
```

`PortScanScheduler` owns the queue, pending correlation map, and one-shot timeout timers. It never creates a second reactor, sleeps, or starts one thread per port. `max_outstanding` bounds active work, and each accepted host/port pair receives a monotonically assigned `PortProbeId`. Results are sorted deterministically by target address, port number, and probe method.

`TcpConnectTransport` opens `AF_INET` or `AF_INET6` stream sockets with `SOCK_CLOEXEC`, sets them nonblocking, handles immediate `connect()` completion and `EINPROGRESS`, and registers a borrowed `io::Event` for writable/error/hangup readiness. Completion reads `SO_ERROR`; success is `OPEN`, `ECONNREFUSED` is `CLOSED`, other socket errors are `UNKNOWN`, and the scheduler deadline produces `FILTERED`. Every terminal path removes the event, cancels the shared timer, closes the descriptor exactly once, and discards the callback.

`TcpSynProbe` reuses `packet::TCP` to construct an offline SYN header. It accepts only a response with matching source/destination ports; SYN/ACK requires acknowledgment equal to the SYN sequence plus one and produces `OPEN`, while a correlated RST produces `CLOSED`. Malformed or unrelated packets do not complete pending work. The legacy parameterless `tcp_syn_network_capability_available()` query remains false because raw capability is runtime- and interface-dependent; the implemented Linux raw transport is selected explicitly and capability-checked rather than silently falling back to fabricated network evidence.

Port selection accepts single values, comma-separated lists, and inclusive ranges. Values outside `1..65535`, malformed tokens, and descending ranges are rejected. The default is the small deterministic set `{22, 80, 443}`; no implicit full-port enumeration exists.

## Service-detection architecture

The Phase 5 execution model is:

```text
Phase 4 PortResult values
          ↓
filter OPEN/TCP results
          ↓
ServiceScheduler
          ↓
bounded target × port × probe queue
          ↓
ServiceProbe::build()
          ↓
ServiceTransport::submit()
       ↙                         ↘
RecordingServiceTransport       ServiceTcpTransport
       ↓                         ↓
synthetic callbacks       Phase 1 IOEngine events
          ↘                         ↙
bounded response accumulation
          ↓
ServiceMatcher
          ↓
ServiceResult
```

`ServiceScheduler` owns the bounded work queue, pending correlation map, retry index, and one-shot `IOEngine` timers. `ServiceTcpTransport` owns nonblocking IPv4 stream sockets, borrowed reactor events, response buffers, and descriptor cleanup. It sends only the payload associated with the selected project-owned probe and never opens a connection for a non-OPEN port result. The recording transport supports deterministic multi-chunk, malformed, oversized, timeout, duplicate, and late-response tests without network access.

The database parser accepts `Probe TCP`, `send`, and `match` records. Match rules are prefix, substring, or ECMAScript regular expression rules with a confidence in `[0,1]`; regular-expression captures can populate product and version templates. Probe ordering prefers a matching port hint, then lower rarity, then generic probes for ports without hints, and finally declaration order. `max_probes` bounds retry depth for each OPEN port.

A successful match produces a `DETECTED` result with service identity, optional product/version/extra fields, confidence, method, probe name, and RTT. A missing response, timeout, connection close without a match, response limit, malformed response, invalid target, or transport failure produces an explicit non-success state. No service identity is inferred solely from a port number.

## OS fingerprinting architecture

The Phase 6 and Phase 14 execution model is:

```text
Phase 4 PortResult / optional Phase 5 context
                    ↓
              OSDetector
                    ↓
              OSScheduler
                    ↓
  bounded TCP SYN/ACK/FIN/NULL/XMAS variants, closed variants, ICMP Echo, UDP fingerprint, UDP Port Unreachable
                    ↓
          OSProbeTransport seam
             ↙                 ↘
 RecordingOSProbeTransport   LinuxOSProbeTransport / injected transport
             ↓
 Phase 1 IOEngine timers and bounded pending map
                    ↓
 packet correlation and typed evidence extraction
                    ↓
 project-owned data/os-fingerprints.db
                    ↓
 weighted available-evidence OSMatcher
                    ↓
 ranked OSDetectionResult
```

`OSDetector` is a thin façade. It accepts the existing `core::Target`, prior TCP `PortResult` values, and optional Phase 5 context. Prior results select an OPEN TCP port when one exists, or the configured explicit port otherwise; they do not become OS evidence. Service names and port numbers are never used to infer an operating-system identity.

The database is a compact, Skan-owned, line-oriented laboratory dataset. It supports comments, blank lines, optional class metadata, typed numeric and boolean fields, bounded numeric ranges, TCP option ordering, UDP payload/response behavior, response presence, deterministic declaration ordering, duplicate rejection, missing metadata rejection, and explicit file-load status. It is not an imported broad fingerprint corpus. Both the CLI and library loader load `data/os-fingerprints.db`; no broad external fingerprint corpus or duplicate signature set is embedded in C++.

The matcher computes confidence from **available observed evidence only**. Absent, timed-out, unsupported, and otherwise unavailable fields do not lower a candidate’s score. Observed mismatches lower the score. Current weights emphasize TCP option ordering, window, MSS, and transport behavior while retaining TTL, DF, window scale, SACK, timestamps, flags, ACK/sequence behavior, response behavior, and ICMP fields. Categories are `NO_MATCH` below `0.30`, `LOW` from `0.30` to below `0.60`, `POSSIBLE` from `0.60` to below `0.85`, and `STRONG` at or above `0.85`. Top-N results sort by descending confidence and then fingerprint name.

Probe lifecycle state is explicit: `Generated`, `Sent`, `ResponseReceived`, `Timeout`, `Unsupported`, or `Malformed`. The model includes TCP SYN/ACK/FIN/NULL/XMAS probes, closed-port variants, ICMP Echo, UDP fingerprint, and UDP Port Unreachable probes. The recording transport supports deterministic injection for every family. `LinuxOSProbeTransport` is selected explicitly and reports `PermissionDenied`, `NotSupported`, interface, capture, and send failures as `UNAVAILABLE` evidence without offline fallback or fabricated identity.

## Phase 7 adaptive timing and scan engine

Phase 7 introduces the protocol-agnostic `scanengine` policy layer above the Phase 1 reactor and below protocol-specific schedulers. It borrows `io::IOEngine`; it does not create sockets, packet formats, protocol transports, or a second reactor.

| Component | Responsibility |
| --- | --- |
| `TimingProfile` | Validated named `T0`–`T5` profiles for parallelism, timeout bounds, RTT multiplier, backoff, recovery, loss EWMA, and retries. |
| `RttEstimator` | Valid-response-only SRTT, RTTVAR, and clamped RTO calculation. |
| `CongestionController` | Bounded parallelism, thresholded timeout backoff, gradual success recovery, and EWMA drop estimation. |
| `ScanWorkItem` / `ScanGroup` | Generic target/protocol metadata, queue ownership, lifecycle state, retry count, and independent metrics. |
| `AdaptiveScheduler` | Shared timer scheduling, bounded pending correlation, injected transport callbacks, retries, cancellation, shutdown, and late/duplicate handling. |
| `TimingController` / `ScanEngine` | Reusable integration seam and validated profile factory for protocol schedulers and independent groups. |
| `ScanMetrics` | Lifecycle, RTT, concurrency, timeout, retry, malformed, duplicate, late, drop, and elapsed-time observability. |

For the first valid RTT sample `R`, `SRTT = R` and `RTTVAR = R/2`. For later samples, `RTTVAR = (1 − β) × RTTVAR + β × |SRTT − R|`, then `SRTT = (1 − α) × SRTT + α × R`, and `RTO = SRTT + multiplier × RTTVAR`. RTO is clamped to the selected profile’s timeout bounds. Timeouts, malformed responses, duplicates, and late responses do not update RTT state.

Adaptive parallelism starts at the profile’s initial value. After the configured consecutive-timeout threshold, it is scaled by the backoff factor and clamped to the minimum. After the configured consecutive-success threshold, it increases by one and is clamped to the maximum. A single timeout does not necessarily halve concurrency, and all profile values are validated before scheduling.

`AdaptiveScheduler` maintains one pending entry per work ID and uses caller-owned one-shot `IOEngine` timers. A timed-out item is retried only while its retry count is below the profile limit; otherwise it becomes terminal. A response for a completed ID is a duplicate, while a response for an expired or cancelled ID is late. Separate `ScanGroup` instances own separate queues and adaptive state.

The existing Phase 4, Phase 5, and Phase 6 schedulers expose an opt-in `adaptive_timing` path backed by `TimingController`. Their established static defaults remain unchanged when the flag is false. Adaptive timing changes scheduling policy only; port state, service matching, OS evidence extraction, and capability checks remain in their existing modules. The CLI adds `--timing T0..T5`, `--min-parallelism`, `--max-parallelism`, and bounded `--retries` to `scan`, while preserving existing target and small default-port behavior.

Phase 7 validation is offline and covers profile validation, RTT equations and bounds, congestion backoff/recovery, state transitions, independent groups, duplicate/late responses, cancellation, retries, shared timers, Phase 4 adaptive integration, and a 1000-item stress group capped at 16 outstanding items. The layer adds no raw packet transport, UDP scanning, public traffic, evasion, exploitation, credentials, or persistence.

## Phase 8 output and result serialization

Phase 8 is a pure presentation layer. It receives an already-computed `output::ScanReport` and performs no scanning, probing, packet construction, detection, scheduling, timing, or network I/O.

```text
Phase 3–7 structured results
            ↓
      output::ScanReport
            ↓
       OutputManager
       ↙    ↓    ↓    ↘
  Normal  JSON  XML  Grepable
```

`ScanReport` is the single canonical model. It contains scanner metadata, optional timestamps/duration/target specification, optional Phase 7 timing profile and `ScanMetrics`, typed `HostResult` values, and top-level warnings/errors. Each `HostResult` contains discovery state, optional hostname/RTT, existing `PortResult` values, existing `ServiceResult` values, ranked existing `OSMatchResult` values, and host-local warnings/errors. No writer defines a second result model or reconstructs data from another writer.

`calculate_summary()` derives host, port, service, and OS counts from the vectors at serialization time. Optional values remain absent, while empty strings, zero values, false values, unknown states, and empty match arrays retain their distinct meanings. `validate_report()` rejects invalid required identifiers, non-finite or out-of-range confidence, negative durations/RTTs, and invalid timing drop rates through `OutputStatus::InvalidReport`.

All writers implement `OutputWriter` and stream directly to a caller-owned `std::ostream`. `OutputManager` only selects the writer. Hosts sort by canonical address, ports by number and protocol, services by associated port with stable probe/service/product/version tie-breakers, and OS matches by descending confidence then ascending name. Invalid UTF-8 is replaced before JSON, XML, or grepable escaping; JSON escapes quotes, backslashes, controls, and newlines, XML escapes attributes/text and sanitizes disallowed controls, and grepable output uses one fixed-field record per line with backslash-escaped quoted values. No machine format emits terminal color codes.

Normal output is composed by `TerminalReportRenderer` from header, host, port-table, summary, and footer components over the same canonical report. `TerminalCapabilities` is detected once at the CLI boundary and carried in `OutputContext`; renderers never read mutable terminal environment state. Width policy is deterministic: plain below 64 columns or for non-TTY output, narrow at 64–87, medium at 88–119, and wide from 120. `TerminalTheme` applies fixed semantic styles only after layout, while `terminal_text` validates UTF-8, removes terminal control hazards, measures display cells, and truncates without splitting code points. Redirected/file normal output remains ASCII and keeps stable Nmap-style host and port rows.

The CLI defaults to `normal` and accepts `--output normal|json|xml|grepable`, `-o <file>`, and `--output-file <file>`. Explicit file output uses RAII and the documented deterministic replace/truncate policy. Serialized output goes to stdout unless a file is selected; operational logs, warnings, and errors go to stderr. Output selection does not add scan logic or alter target/port scope.

## Phase 9 network transport and packet capture

Phase 9 is a low-level infrastructure layer between already-composed Phase 2 frames and future correlation consumers. Its dependency direction is intentionally narrow:

```text
packet::Packet serialization
          ↓
      net::Transport
          ↓
   explicit Linux interface
          ↓
      net::PacketCapture
          ↓
    net::PacketReceiver
          ↓
 Phase 2 protocol parsers
          ↓
  PacketObservation / filters
          ↓
 Future scan correlation
```

`NetworkInterface` is a strongly typed value containing an interface name, kernel index, IPv4 addresses and prefix lengths, operational state, and distinct capture/injection capability flags. `enumerate_interfaces_result()` uses Linux `getifaddrs()` and exact kernel interface indexes, sorts by name, and exposes structured errors. Capability flags are obtained by probing the ability to create and bind an `AF_PACKET` raw socket; no packets are transmitted during enumeration. `find_interface()` is exact-name lookup. There is no automatic interface selection for privileged injection.

`Transport` knows only about moving caller-provided bytes. `RecordingTransport` stores exact frames without network access, and `NullTransport` intentionally performs no transmission. `LinuxTransport` requires an explicit interface name, opens an `AF_PACKET` socket, binds it to that interface, supports configured nonblocking sends, preserves system errors, and owns the descriptor through `detail::UniqueFd`. It does not choose ports, construct scan strategies, alter bytes, spoof source identity, fragment frames, or hide traffic.

`PacketCapture` is independent of scanning. `RecordingCapture` provides deterministic queued frames. `LinuxCapture` requires an explicit interface, binds a nonblocking `AF_PACKET` socket, uses bounded `recvmsg(MSG_TRUNC)`, reports `WouldBlock`/`OversizedFrame`/receive failures explicitly, and never allocates based on an untrusted frame size. `PacketReceiver` copies only bounded frames and invokes the existing Phase 2 Ethernet, IPv4, TCP, UDP, and ICMP parsers. `ParseStatus` distinguishes empty, truncated, malformed, unsupported, and valid observations. No recursive packet-dissection framework is introduced.

`PacketReceiver::attach()` registers the capture descriptor with the existing borrowed-event `io::IOEngine`; it does not create another reactor, polling loop, sleep timer, worker thread, or thread-per-packet mechanism. `PacketFilter` supports only `Any`, IPv4, TCP, UDP, ICMP, source-port, and destination-port predicates. `CorrelationTable` supplies deterministic insertion, lookup, duplicate detection, removal, timeout cleanup, and late-packet rejection without implementing a complete scanner.

The CLI adds only infrastructure inspection:

```text
  skan interfaces [--json] [--interface <name>]
```

Normal output lists interface name, index, IPv4/prefix values, state, capture capability, and injection capability. JSON output follows stable interface/address ordering and contains only interface data. A selected interface is reported as not found rather than silently replaced with another interface. Opening Linux transport or capture returns `PermissionDenied`, `InterfaceNotFound`, `NotSupported`, or another structured status as appropriate; it never returns fake success when the capability is absent.

> Skan's network transport is capability-honest. When packet capture or injection is unavailable, Skan reports the unavailable capability and does not fabricate successful network operations or packet responses.

The Linux implementation is intentionally Linux-specific and privilege-dependent. Controlled integration tests use only the local `lo` interface, feed serialized bytes through `RecordingTransport`, and report `SKIPPED` when raw packet capture is unavailable. Phase 9 does not implement stealth, decoys, source spoofing, packet evasion, IDS/IPS bypass, fragmentation attacks, covert channels, firewall bypass, credential attacks, exploitation, persistence, Internet-wide scanning, or public-target traffic.

## Phase 10 real network integration

Phase 10 connects existing scheduler seams to Phase 9 Linux infrastructure without moving scan strategy into the transport layer:

```text
PortScanScheduler / Discovery
          ↓ existing callback seam
LinuxNetworkScanTransport / LinuxDiscoveryTransport
          ↓
LinuxTransport + LinuxCapture + PacketReceiver
          ↓ one shared IOEngine
correlated PortResponse / DiscoveryResponse
          ↓
existing result, timing, and Phase 8 report paths
```

`LinuxNetworkScanTransport` implements `portscan::PortScanTransport`. On `open()`, it requires an explicit interface, validates an IPv4 address on that interface, opens the Phase 9 Linux transport and capture resources, and registers the capture descriptor with the existing `IOEngine`. On submission, it reuses the Phase 4 `TcpSynProbe` bytes, composes them through the existing Phase 2 `Packet` model into an Ethernet/IPv4/TCP frame, records a strong target/source-port/destination-port/sequence correlation key, and sends only after the correlation entry is ready. Captured TCP observations are filtered and correlated by address, ports, and acknowledgment-derived sequence before the original Phase 4 callback receives a `PortResponse`. The existing scheduler remains responsible for SYN+ACK/RST classification, timeouts, retries, RTT, adaptive timing, and `PortResult` creation.

`LinuxDiscoveryTransport` implements the existing Phase 3 `DiscoveryTransport` seam and feeds a callback owned by the `Discovery` wrapper. It composes ICMP Echo and TCP discovery packets through Phase 2 and uses the dedicated `discovery::ArpMessage` for Ethernet ARP requests. Matching ICMP, TCP, and ARP observations become existing `DiscoveryResponse` values; unrelated frames are ignored. Discovery’s established aggregation remains authoritative: only a matching response proves `UP`, while timeout remains `UNKNOWN`. The adapter owns descriptors and pending receive correlation but does not parse results into a new model or select probe strategy.

The adapter’s `ScanSession` records selected interface, lifecycle, transport/capture status, submission/completion/failure counters, and start time. Shutdown clears pending correlation, detaches the capture event through `PacketReceiver`, closes capture and transport RAII descriptors, and prevents callbacks after closure. No second reactor, polling loop, sleep, worker thread, or thread-per-probe path exists.

The CLI exposes explicit execution modes:

```text
  skan scan <ipv4> --method connect
      → existing normal nonblocking TCP Connect transport
  skan scan <ipv4> --transport offline --method syn
      → deterministic recording transport; no network access
  skan scan <ipv4> --transport linux --interface <name> --method syn
      → explicit Linux AF_PACKET transport/capture
  skan discover <ipv4> --transport linux --interface <name>
      → explicit Linux discovery transport/capture
```

SYN raw transport is never selected implicitly. Connect mode never switches to AF_PACKET, and Linux mode never silently falls back to Connect. Missing interface, missing IPv4 configuration, raw-socket permission failure, missing neighbor context, malformed frame, and unsupported capability remain explicit errors or unavailable outcomes. The service detector continues to use its existing bounded normal TCP stream transport because service probes are stream exchanges. The OS detector remains unavailable when its required live probe transport is not implemented; its existing `UNAVAILABLE`/empty-match/zero-confidence result is preserved rather than replaced with a guessed platform identity.

> Skan's network transport is capability-honest. When packet capture or injection is unavailable, Skan reports the unavailable capability and does not fabricate successful network operations or packet responses.

## Correlation and response lifecycle

Each outbound submission contains a monotonically assigned `ProbeId`, target address, probe type, serialized packet, and protocol-specific correlation metadata. The scheduler stores the sent monotonic timestamp and deadline in its pending entry.

When a response arrives, the scheduler first looks up the `ProbeId`. An unknown ID is reported as not found without a state mutation. An expired ID is counted as late; a completed ID is counted as a duplicate. A pending response is passed to the probe implementation, which rejects malformed input without out-of-bounds access and ignores valid but unrelated packets. Only a matching response removes the pending operation, cancels its Phase 1 timer, calculates RTT, and appends positive evidence.

Malformed responses for a known pending probe are recorded as `MALFORMED_RESPONSE`, complete that probe, cancel its deadline, and return `ParseError`. This prevents a malformed packet from causing an additional timeout result. Unrelated responses leave the pending operation untouched.

## Timeout model

Every accepted probe receives a one-shot `IOEngine::schedule()` timer using `std::chrono::steady_clock`. The scheduler never calls `sleep()` and never blocks a thread per host. On expiry, the pending operation is removed, a `TIMEOUT` result with no RTT is recorded, and queued work is pumped within the configured `max_outstanding` bound.

The shared Phase 1 timer implementation is reused directly. No new timer queue or deadline clock exists in the discovery layer. When all queued and pending probes are complete, the scheduler requests a clean stop from the shared event loop, allowing finite CLI and integration runs.

## Host-state aggregation

Evidence is retained per target address and exposed through `DiscoveryResult` values. Aggregation is deterministic:

1. Any positive response (`UP`) wins immediately, including when another probe timed out.
2. Explicit `DOWN` evidence would be considered only if there is no positive evidence.
3. Timeout, malformed, invalid, unrelated, and absent evidence do not prove that a host is down; absent conclusive evidence remains `UNKNOWN`.

Phase 3 currently produces positive or unknown outcomes. It intentionally does not manufacture `DOWN` from a timeout.

## Packet Layer integration

Discovery does not duplicate protocol serialization. ICMP and TCP probe builders call the Phase 2 `ICMP` and `TCP` models. ARP is the only discovery-local wire representation because ARP was intentionally not added to the Phase 2 IP-focused packet layer. The packet layer remains responsible for byte ordering, header layout, checksums, serialization bounds, and protocol-local parsing.

## I/O Engine integration

The public discovery, port-scan, service-detection, and OS-detection APIs accept an existing `io::IOEngine&`. Probe deadlines use its monotonic timer service, and scheduler completion requests its `stop()`. The recording transports are injectable seams and do not own an event loop. The real Connect transports borrow the same reactor and own only their socket/event lifecycles. Phase 9 `PacketReceiver::attach()` registers a Linux capture descriptor as another borrowed event with the same reactor. Phase 10 Linux scan and discovery adapters use that same registration path and pass matching responses back through the existing scheduler callbacks. The receiver owns only its bounded buffer and event object, while Linux transport/capture classes own their descriptors. All schedulers and receiver callbacks remain single-thread-affine like the reactor.

## CLI boundary

The CLI retains `--version`, `--help`, and the Phase 3 discovery command. Phase 4 adds the scoped TCP scan, Phase 5 adds opt-in service detection, Phase 6 adds the capability-honest OS detection command, Phase 8 adds pure result-format selection for `scan`, Phase 9 adds infrastructure interface inspection, and Phase 10 adds explicit offline/Linux transport selection:

```text
  skan scan <ipv4-address> [--tcp-ports <single,list,range>]
          [--method <connect|syn>] [--transport <offline|linux>]
          [--interface <name>] [--timeout-ms <ms>]
          [--max-outstanding <n>] [--service-detect]
          [--service-db <path>] [--max-response-bytes <n>]
          [--max-probes <n>] [--output <normal|json|xml|grepable>]
          [-o|--output-file <path>]
  skan os-detect <ipv4-address> [--os-db <path>]
          [--timeout-ms <ms>] [--max-outstanding <n>] [--json]
  skan discover <ipv4-address> [--icmp|--tcp|--arp]
          [--transport <offline|linux>] [--interface <name>]
  skan interfaces [--json] [--interface <name>]

```

The scan command validates explicit IPv4 targets before running. `scan --method connect` uses real nonblocking stream sockets unless `--transport offline` is selected. `scan --method syn` requires `--transport offline` or `--transport linux --interface <name>`; Linux mode uses the Phase 10 adapter and reports capability failures without fallback. `--service-detect` runs only after the scan and only for OPEN TCP results through the existing bounded stream transport. `discover --transport linux` requires an explicit interface and uses the Phase 10 discovery adapter; the default discovery path remains offline. `os-detect` loads the project-owned database and then reports live capability unavailability in this build; its `--json` form emits structured unavailable state with empty matches and confidence `0`. Phase 8 output defaults to Normal, accepts `normal`, `json`, `xml`, and `grepable`, and supports explicit RAII file replacement through `-o`/`--output-file`. Serialized stdout is kept separate from stderr diagnostics. There is no live UDP scanner, evasion, or range-expansion option.

## Error model

Discovery maps invalid IPv4 input to `InvalidArgument` and `INVALID_TARGET`, transport I/O failure to `IoError` and `SOCKET_FAILURE`, parser rejection to `ParseError` and `MALFORMED_RESPONSE`, timer or internal construction failures to `InternalError`, and late responses to `NotFound` without corrupting state. Port scanning maps Connect success to `OPEN/IMMEDIATE_SUCCESS`, refusal to `CLOSED/CONNECTION_REFUSED`, deadline expiry to `FILTERED/TIMEOUT`, and other local socket failures to `UNKNOWN/SOCKET_ERROR`. SYN capability absence is explicit `PermissionDenied`/`CAPABILITY_UNAVAILABLE`; malformed and unrelated synthetic responses leave pending state unchanged. Service detection maps timeout, close, oversized response, malformed response, invalid target, no match, and transport failure to explicit `DetectionError` values without fabricating a service identity.

## Phase 11 unified scan orchestrator

Phase 11 is a coordination layer over Phases 0–10. It does not introduce a new network engine, packet format, scheduler family, timing implementation, matcher, database corpus, or output writer. The public `ScanOrchestrator` facade constructs a `ScanPipeline`; the pipeline owns a `ScanSession`, stage adapters, and the accumulated existing result types. `ScanSession` owns exactly one `io::IOEngine`, which is borrowed by the existing asynchronous schedulers and transports throughout the run.

```text
explicit core::Target values
          |
          v
     ScanConfig validation
          |
          v
     ScanOrchestrator / ScanPipeline
          |
          +--> DiscoveryStage -------> Discovery + selected transport
          |
          +--> PortScanStage --------> PortScanScheduler + selected transport
          |
          +--> ServiceDetectionStage -> ServiceDetector + ServiceTransport
          |
          +--> OSDetectionStage ------> OSDetector + injected/capability seam
          |
          +--> ScanReportBuilder ----> canonical output::ScanReport
          |
          +--> OutputManager --------> normal / JSON / XML / grepable
```

### Pipeline state and event contract

The state machine is explicit: `Created`, `Initializing`, `Discovering`, `PortScanning`, `DetectingServices`, `DetectingOS`, `Serializing`, `Completed`, `Failed`, and `Cancelled`. Configuration validation and target aggregation happen before operational stages. Disabled stages are skipped by a direct valid transition to the next enabled stage or serialization; an invalid transition is rejected by `ScanSession` rather than silently mutating state.

Typed `ScanEvent` values provide stable stage and lifecycle notifications. A successful run emits `ScanStarted`, zero or more `StageStarted`/`StageCompleted` pairs for enabled stages, `Serializing`, and `ScanCompleted`. Warnings and errors are emitted at the point where existing subsystem status is translated. A cancellation emits `ScanCancelled` once and prevents subsequent completion events. Events emitted after a terminal state are ignored, and repeated cancellation is idempotent.

The CLI may attach `TerminalProgressRenderer` as a presentation-only event sink when normal output is going to an interactive stdout and stderr is also interactive. It uses fixed labels and completed-result counters, throttles repeated batch updates, clears before the Output stage serializes the report, and never computes rate or ETA from post-stage events. File/machine output, one-sided redirection, `TERM=dumb`, and debug logging disable progress. Observer failures remain isolated by `ScanSession::emit()` and cannot change scan state.

| Pipeline concern | Phase 11 responsibility | Existing implementation retained |
| --- | --- | --- |
| Target scope | Aggregate explicit targets and preserve host ordering. | `core::Target` and `core::Host` validation. |
| Discovery | Invoke only when enabled and pass discovered-UP hosts onward. | Phase 3 `Discovery`, scheduler, probes, timers, and Phase 10 Linux adapter. |
| Ports | Invoke the bounded port scheduler for the selected method. | Phase 4 scheduler, Connect transport, SYN model, and Phase 10 network adapter. |
| Services | Submit only OPEN TCP results after port completion. | Phase 5 stream transport, detector, probe database, and matcher. |
| OS | Preserve existing injected/unsupported behavior without guessing. | Phase 6 detector, evidence model, database, and matcher. |
| Timing | Pass the validated Phase 7 profile and bounds. | Timing controller, RTT estimator, congestion controller, and schedulers. |
| Output | Build and serialize one canonical report. | Phase 8 `ScanReportBuilder` boundary and `OutputManager`. |

### Configuration and transport policy

`ScanConfig` defaults are deliberately compatible with the earlier `scan` command: TCP Connect, no discovery, no service detection, no OS detection, the existing Phase 4 default ports when the port vector is empty, the Phase 7 default timing profile, bounded timeout and parallelism, normal output, and no file. Validation rejects empty or invalid typed targets, malformed IPv4/IPv6 addresses, port zero, invalid positive bounds, incompatible method/transport combinations, missing Linux interface requirements, unsupported discovery transport selections, invalid service limits, invalid timing profiles, and unusable output paths.

Offline mode uses the existing recording transports and is deterministic. Linux mode is selected explicitly and uses the Phase 10 adapters; raw capability or interface failures are surfaced as errors. There is no implicit fallback from Linux to offline. Explicit targets are the only supported scope mechanism, so Phase 11 adds no CIDR or range parser.

### Stage boundary and cancellation semantics

Each adapter translates `ScanConfig` into the existing subsystem configuration and delegates submission, callback correlation, timeout handling, bounded concurrency, and result collection to that subsystem. The pipeline does not create worker threads or a second event loop and does not poll or sleep. The active stage is retained only long enough to collect its result; cancellation destroys or cancels it through its existing lifecycle and then stops the shared session reactor.

Cancellation may occur before `run()`, between stages, or from an event sink. It is cooperative and idempotent. The pipeline stops starting later stages, closes active scheduler/transport resources through their existing cancellation paths, maps all results collected so far, and still serializes a valid partial report through `OutputManager`. In particular, a discovery timeout remains `UNKNOWN`, and an unavailable live OS transport yields a warning with no fabricated match, empty match list, and zero confidence.

### Canonical report mapping

`ScanReportBuilder` is the sole Phase 11 conversion boundary. It combines explicit target hosts, discovery results, port results, service results, and OS results into Phase 8 `output::HostResult` and `output::ScanReport` values. Host and child-result ordering is deterministic, unknown states and RTTs are retained, and derived summary counters come from the existing Phase 8 summary calculation. The pipeline never hand-builds JSON, XML, normal, or grepable output; `OutputManager` remains the only serialization boundary, and its file writer uses replacement/RAII semantics.

### Failure and capability model

A configuration failure occurs before network work and is returned as an invalid-argument status. A stage submission, transport, timer, parser, or internal construction error produces a typed pipeline error and a diagnostic event; the session enters `Failed` unless cancellation has already won the race. Scheduler timer-registration failure is terminal for the affected logical work item and cannot leave an unbounded pending entry. Late and duplicate responses remain governed by the existing schedulers and cannot corrupt pending state. Linux AF_PACKET tests may skip when the environment lacks permission; a real Linux scan instead fails clearly and never reports offline data as live evidence.

### Audit hardening

The Phase 1 reactor dispatches epoll records through opaque per-registration tokens rather than raw `Event*` payloads. After every callback it revalidates the token mapping before touching the event, so callback-time cross-event removal and stale records from one `epoll_wait` batch cannot dereference destroyed events. Reactor shutdown detaches borrowed registrations and clears timers; event ownership remains with callers as documented.

`PacketReceiver` clamps parser input to the Ethernet maximum frame size and its attached descriptor follows the shared reactor’s removal lifecycle. Linux TCP SYN transport teardown clears both pending submissions and correlation entries, and session identifiers are adapter-owned rather than process-global mutable state. Valid unknown TCP option kinds are skipped with strict length checks so legal future options do not make an otherwise usable response malformed; the public model still exposes only recognized options.

The optional `make fuzz` target builds an offline libFuzzer harness when Clang’s fuzzer runtime is available. The harness feeds arbitrary in-memory bytes to Ethernet, IPv4, TCP, UDP, ICMP, service-database, OS-database, port-selection, timing-profile, and target-spec parsers. Missing fuzz tooling is reported as `SKIPPED`, not treated as a successful fuzz run. Phase 12 now implements the dedicated target resolver for IPv4, CIDR, ranges, mixed targets, normalization, deduplication, and deterministic expansion; later asynchronous DNS can replace the injected synchronous resolver boundary without changing the scanner.

Phase 11 tests cover state and event contracts, report ordering, adapter delegation, deterministic offline execution, cancellation, multi-host sequencing, discovery response handling, service/OS stage order, and a bounded 1,000-host × 100-port workload. Timer and correlation tests cover 10,000 same-deadline timers and 10,000 live correlation entries. Port and service schedulers defer deterministic result sorting until their result vectors are observed, avoiding quadratic repeated sorting while preserving the public ordered-result contract. This preserves the existing Phase 0–10 tests and keeps capability-dependent raw-network tests environment-aware.

## Phase 12 target resolution and target engine

Phase 12 is a boundary subsystem between CLI text and the Phase 11 orchestrator:

```text
CLI target specification
          ↓
TargetParser
          ↓
TargetResolver / platform A-record resolver
          ↓
TargetNormalizer
          ↓
TargetDeduplicator
          ↓
deterministic TargetSet<uint32_t IPv4>
          ↓
core::Target / core::Host conversion at the CLI boundary
          ↓
Phase 11 ScanOrchestrator
```

`TargetSpec` carries a typed kind and parsed values for IPv4/IPv6 addresses, hostnames, CIDRs, or inclusive ranges. `ResolvedTarget` carries a typed binary IPv4/IPv6 identity and optional source-hostname metadata. `TargetSet` owns normalized values. The implementation exposes explicit `TargetParser`, `TargetResolver`, `TargetNormalizer`, and `TargetDeduplicator` boundaries, with `TargetEngine` as the composed façade.

Parsing accepts strict IPv4/IPv6 literals, IPv4 `/0` through `/32` and IPv6 `/0` through `/128` CIDR, non-reversed ranges, DNS hostname syntax, and comma-separated mixtures with surrounding whitespace. Network and broadcast addresses are retained because the target engine represents the exact requested address space. Hostnames use `getaddrinfo()` with `AF_UNSPEC` and bounded A+AAAA results. The synchronous platform resolver runs at CLI/startup before the shared Phase 1 reactor enters its event loop. An injectable resolver boundary supports later asynchronous resolution without moving blocking DNS into an IOEngine callback.

Expansion is protected by `TargetLimits::max_targets`, defaulting to 4,096, and `max_hostname_results`, defaulting to 64 per hostname. CIDR/range cardinalities are checked before iteration, duplicates are tracked by binary family-aware identity, and the final vector is sorted once by typed family and address bytes. The engine returns typed `TargetErrorCode` values including `INVALID_IPV4`, `INVALID_CIDR`, `INVALID_RANGE`, `INVALID_HOSTNAME`, `RESOLUTION_FAILED`, `RESOURCE_EXHAUSTED`, and `EMPTY_TARGET_SET`; it never silently truncates. `core::StatusCode::ResourceExhausted` carries resource-limit failures across the existing status boundary.

The CLI provides `resolve <target-spec> [--max-targets N] [--max-hostname-results N] [--json]`. Default output is one normalized IPv4/IPv6 address per line; JSON output is a compact `targets` array with an explicit family field. `scan <target-spec>` resolves before constructing `core::Target`, then passes the same existing Phase 11 configuration and stage pipeline. `discover` accepts numeric IPv4/IPv6 addresses for offline probe construction; Linux IPv6 discovery is explicitly unavailable. `os-detect` accepts IPv6 targets but returns structured unavailable evidence rather than running IPv4-only probes. The Target Engine does no scanning or transport work, and the scan orchestrator does no target parsing or expansion.

## Platform and network boundary

Phase 3 is Linux-first because Phase 1 uses Linux `epoll`; Phase 9/10 additionally use Linux interface and raw-packet capabilities. Default tests and default CLI paths do not require raw-network privileges, external hosts, or public Internet access.

Phase 9 contains the repository's explicit `AF_PACKET` raw-socket byte transport and bounded capture. Phase 10 connects these resources to the existing TCP SYN and discovery seams only when explicitly requested. The repository still contains no live UDP scanner, alternate TCP flag scan, live OS fingerprint transport, Lua, evasion, dashboard, or hidden scope-control mechanism. Phase 6’s OS layer is packet-model-backed and synthetic/injected only. Phase 4 contains a scoped IPv4 TCP Connect transport and deterministic TCP port enumeration after normal target validation. Phase 5 contains only TCP stream banner/probe detection on OPEN results through `ServiceTransport`; it does not perform service exploitation, credential exchange, or Internet-wide scanning. Phase 9/10 transport and capture require explicit interfaces and report privilege/capability failures instead of fabricating network results.

## Module status

| Module | Responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Implemented in Phase 0 |
| I/O Engine | Linux epoll event dispatch, timers, and descriptor operations | Implemented in Phase 1 |
| Packet Layer | Ethernet, IPv4, TCP, UDP, ICMP representation, composition, checksums, serialization, and parsing | Implemented in Phase 2 |
| Host Discovery | Bounded, asynchronous ICMP/TCP/ARP probe scheduling and response aggregation | Implemented in Phase 3 |
| Scan Engine | Scan-job coordination and lifecycle management | Phase 4 scheduler implemented |
| Port Scanning | TCP port selection, Connect transport, SYN probe seam, state/result collection | Phase 4; Phase 10 explicit Linux SYN adapter |
| Detection | Bounded TCP banner/probe service detection and deterministic matching | Implemented in Phase 5; OS architecture in Phase 6 |
| OS Detection | Typed evidence collection, bounded injected scheduling, reduced fingerprint database, and weighted matching | Phase 6 complete for synthetic/injected scope; live raw transport unavailable |
| Data Layer | Project-owned service and OS fingerprint databases plus future persistence and serialization | Phase 5/6 compact datasets implemented; persistence planned |
| Lua Scripting | Optional user-defined scripting extensions | Planned |
| Output | Pure Normal, JSON, XML, and grepable serialization of canonical reports | Phase 8 implemented |
| Network | Interface enumeration, capability reporting, offline transports/capture, Linux AF_PACKET transport/capture, bounded receiver, filters, correlation boundary, and Phase 10 scheduler adapters | Phase 10 implemented; Linux raw sockets remain privilege-dependent |
| Evasion | Future traffic and timing controls | Planned |
| CLI | Version/help bootstrap, discovery exercise, scoped TCP scan, opt-in service detection, capability-honest os-detect, output selection/file output, infrastructure interface inspection, and explicit transport selection | Phase 10 integration complete |
| Dashboard | Future TypeScript/React visualization and management interface | Planned |


## Phase 13 UDP scan architecture

Phase 13 adds a sibling UDP subsystem rather than forcing datagram semantics into the TCP-specific `PortSubmission`, `PortResponse`, or `PortProbe` contracts. `UdpScanStage` owns selection of the project-owned UDP probe database and transport. `UDPScheduler` owns a bounded host × UDP-port queue, one logical probe identifier per attempt, deterministic source-port allocation, retry/timer lifecycle, and canonical `PortResult` emission. It borrows the same Phase 1 `IOEngine` and optional Phase 7 `TimingController` used by the existing schedulers.

```text
TargetEngine-normalized core::Target
                    ↓
             UdpScanStage
                    ↓
              UDPScheduler
          ↙                     ↘
RecordingUDPTransport     LinuxUDPScanTransport
          ↓                     ↓
 injected UDPResponse       LinuxTransport + LinuxCapture
                                ↓
                    PacketReceiver / ICMPv4 parser
                                ↓
             UDP response or embedded-error correlation
                                ↓
             OPEN / CLOSED / FILTERED / OPEN_OR_FILTERED
                                ↓
                       canonical PortResult
```

The pipeline order is `Discovery → TCP Port Scan → UDP Scan → Service Detection → OS Detection → Output`, with each stage still independently optional according to configuration. TCP service detection receives only the TCP result vector, and OS detection filters the merged vector back to TCP before invoking the existing OS subsystem. UDP results are merged into the report after service detection, so UDP evidence is visible in all output formats without changing the TCP service or OS contracts.

### UDP packet and error correlation

Probe packets are composed through `packet::UDP` and `packet::Packet`; no UDP wire serialization is duplicated in the scheduler or transport. Linux capture continues through the existing bounded `PacketReceiver`. ICMPv4 Destination Unreachable is accepted by the existing ICMP model only after header-length and Internet-checksum validation. The Linux UDP adapter then validates the embedded IPv4 version, IHL, total length, IPv4 checksum, UDP protocol, UDP length, and all embedded address/port fields before generating a typed response.

The logical probe ID is carried by the callback lifecycle. For captured packets, the dedicated UDP pending map performs strong wire matching on local/source IPv4, target/destination IPv4, source port, destination port, and UDP protocol. For ICMP errors, matching additionally requires an outer error source equal to the target and an embedded IPv4/UDP packet equal to the original local probe. Ambiguous, malformed, unrelated, late, and duplicate observations are ignored or converted to an explicit error without completing a different pending item. Source ports are deterministic and bounded to a fixed ephemeral allocation range, unique among outstanding entries, and released on every terminal, retry, cancel, and teardown path.

### State and transport boundaries

A validated target UDP datagram produces `OPEN` with `UDP_RESPONSE`. An embedded ICMP Destination Unreachable code 3 produces `CLOSED` with `ICMP_PORT_UNREACHABLE`. Administrative codes produce `FILTERED` with an administrative reason, and network/host unreachable codes produce `FILTERED` with a network-unreachable reason. Exhausting the bounded retry policy produces `OPEN_OR_FILTERED` with `UDP_TIMEOUT`; silence is never collapsed into `CLOSED`, `OPEN`, or fabricated service evidence. Malformed correlated data and local transport failures use `ERROR` with an explicit reason. The canonical summary retains additive counters for open-or-filtered, unfiltered, and error results while preserving the legacy TCP counters.

`RecordingUDPTransport` is deterministic and injection-only. `LinuxUDPScanTransport` reuses the existing interface lookup, Linux byte transport, bounded capture, packet receiver, and single-reactor attachment lifecycle. It requires an explicit interface and host AF_PACKET capture/injection capability. A failed Linux open is returned as a typed capability or system error; there is no automatic offline fallback. Connect transport is rejected for UDP rather than being silently reinterpreted as a stream scan.

The project-owned `data/udp-probes.db` parser rejects malformed records, duplicate names or destination ports, invalid hexadecimal payloads, oversized payloads, invalid response limits, and multiple default records. Each record is small and bounded; the built-in dataset covers minimal DNS, NTP, SNMP, NetBIOS, TFTP, IKE, and generic fallback probes. No Nmap database or broad external probe corpus is used.


## Phase 14 live OS fingerprinting

Phase 14 extends the existing OS architecture rather than introducing a second networking stack. `OSDetectionStage` chooses an injected, offline recording, or explicit Linux transport. `LinuxOSProbeTransport` owns one `LinuxTransport`, one `LinuxCapture`, one bounded `PacketReceiver`, and one shared `io::IOEngine` attachment. It uses the existing `packet::Packet` composition boundary for Ethernet, IPv4, TCP, UDP, and ICMP serialization. It does not hand-serialize protocol headers, open a second reactor, create worker threads, poll in a loop, or silently fall back when AF_PACKET capability is absent.

The live execution path is:

```text
normalized core::Target
        ↓
OSDetectionStage / OSDetector
        ↓
OSScheduler: bounded deterministic probe queue
        ↓
OSProbe::build(): TCP SYN/ACK/FIN/NULL/XMAS, ICMP Echo, UDP
        ↓
LinuxOSProbeTransport::submit()
        ↓
packet::Packet composition → LinuxTransport send
        ↓
LinuxCapture → PacketReceiver → bounded observation
        ↓
strong response correlation by address, protocol, ports, sequence, and ICMP quote
        ↓
OSProbe::assess(): matching / unrelated / malformed
        ↓
ObservedOSFingerprint → OSMatcher → OSDetectionResult
        ↓
ScanReportBuilder → HostResult → all output writers
```

TCP correlation validates the local and remote IPv4 addresses, response source/destination ports, and the acknowledgment relation to the submitted sequence. UDP correlation validates the local/remote addresses and reversed response ports. ICMP Destination Unreachable correlation validates the outer source/destination addresses and the quoted IPv4 header, quoted protocol, and quoted transport ports. ICMP port-unreachable evidence is distinct from a valid UDP datagram response. The quoted packet parser accepts only the bounded bytes required by ICMPv4 and never reads beyond the capture buffer. Completed, cancelled, expired, unrelated, duplicate, and malformed observations cannot mutate another pending probe.

The probe database parser is strict and deterministic. It rejects malformed numeric values, descending ranges, duplicate fields, duplicate fingerprint names, unsupported fields, and missing required metadata. Optional Class version/device columns remain optional. UDP signatures include bounded payload-length ranges, response behavior, and response presence. The matcher computes confidence only over available evidence and preserves unavailable/malformed/timeout counters in `OSDetectionResult`; it does not infer an operating-system identity from a port number, service label, local platform, or missing response.

`OSDetectionResult` is propagated into the canonical report in addition to the legacy sorted match vector. Normal, JSON, XML, and grepable writers expose explicit state and error values, confidence, sent/received/timeout counters, RTT when available, and TCP/ICMP/UDP evidence counts. This makes a live capability failure observable as `UNAVAILABLE` rather than indistinguishable from an empty match list.

| Capability boundary | Required behavior |
| --- | --- |
| Offline transport | Execute the same typed scheduler and matcher without network descriptors; no live evidence is fabricated. |
| Injected transport | Provide deterministic serialized packet responses for unit and integration tests, including UDP and ICMP-error evidence. |
| Linux AF_PACKET | Require an explicit interface, discover a usable local IPv4 source, attach capture to the existing reactor, and report permission/not-supported/send/capture failures explicitly. |
| Unsupported transport | Do not reinterpret Connect sockets as OS packet probes and do not silently downgrade a requested Linux run to offline mode. |

Phase 15 adds bounded IPv6 parsing and offline/Connect dual-stack behavior while keeping native Linux raw IPv6 and IPv6 OS fingerprinting unavailable. It does not add TCP option evasion, decoys, spoofing, fragmentation, credential handling, exploitation, service inference, or public-target traffic.


## Phase 15 — IPv6 foundation and dual-stack boundaries

Phase 15–16 preserve the Phase 0–14 architecture and extend the existing contracts with typed dual-stack identity. `core::IpAddress` stores an address family and binary bytes; canonical text formatting is a presentation concern. `core::Host`, `target::ResolvedTarget`, probe submissions, correlation keys, and `output::HostResult` carry the typed identity. Equality, hashing, deduplication, filtering, and ordering therefore cannot confuse an IPv4 address with an IPv6 address that has similar text or mapped representation.

The target path is:

```text
CLI target text
      ↓
TargetParser
      ↓
synchronous bounded getaddrinfo(AF_UNSPEC)
      ↓
TargetResolver / TargetNormalizer / TargetDeduplicator
      ↓
deterministic typed TargetSet
      ↓
existing ScanOrchestrator and ScanPipeline
```

IPv4 and IPv6 literals, one validated IPv6 `%zone` token, CIDR, inclusive ranges, comma-separated mixtures, and bounded A+AAAA hostname resolution are handled before the shared reactor starts. IPv6 CIDR/range expansion performs size checks before iteration and never materializes an uncontrolled address space. Hard ceilings bound target and hostname expansion, and a zone resolves only an explicitly named or numeric interface. Downstream modules receive only normalized hosts and do not add another target parser.

The packet path remains singular:

```text
Ethernet II
    ↓ EtherType 0x0800 or 0x86DD
IPv4 or strict IPv6 base header
    ↓
bounded IPv6 extension parser when required
TCP / UDP / ICMPv4 / ICMPv6
    ↓
PacketReceiver observations
    ↓
family-aware filters and one correlation boundary
```

The IPv6 packet model validates the fixed 40-byte base header, version, payload length, traffic class, flow label, next-header, hop-limit, and binary addresses. The shared extension parser recognizes Hop-by-Hop Options, Routing, Fragment, and Destination Options headers under explicit count and byte budgets and returns typed malformed, unsupported, or limit outcomes. The quoted-IPv6 parser reuses those bounds to extract only validated UDP identity fields from ICMPv6 errors. It is a recognition/parser boundary, not a fragmentation or evasion mechanism. TCP, UDP, and ICMPv6 checksums use the RFC-style IPv6 pseudo-header through one shared checksum helper; receive validation rejects bad TCP/UDP checksums, permits zero IPv4 UDP checksums, and rejects zero IPv6 UDP checksums.

The same Phase 1 `io::IOEngine`, event lifecycle, one-shot timers, schedulers, capture path, and output model are reused for both families. AF_INET6 TCP Connect and bounded service detection use the existing nonblocking stream lifecycle. Offline discovery, UDP construction, ICMPv6 Echo/error correlation, scoped SYN construction, and synthetic receiver/correlation tests use the existing recording/injected seams. Interface enumeration exposes typed IPv6 addresses and family-specific capability fields. Canonical reports carry `family=ipv4` or `family=ipv6`; JSON, XML, normal, and grepable writers expose it without reconstructing another report model.

Linux raw IPv6 capture/injection is an explicit unavailable capability in this phase. The existing Linux discovery, raw SYN, raw UDP, and live OS adapters remain IPv4/ARP-specific and require an explicitly selected interface. An IPv6 request to those paths returns an explicit unavailable/capability error; it is never changed to offline or Connect mode, and no interface is selected implicitly. IPv6 OS fingerprinting returns structured `UNAVAILABLE` with zero confidence rather than deriving identity from address, port, service, or local platform data. Limited ICMPv6 Neighbor Discovery recognition does not claim a complete ND implementation.

Phase 16 introduces no second reactor, worker threads, polling loops, sleeps, duplicate packet stack, evasion, spoofing, decoys, fragmentation attacks, exploitation, credentials, persistence, or public-target traffic. Native Linux raw IPv6 discovery/SYN/UDP, complete ND, and IPv6 OS fingerprinting remain explicit unavailable capabilities; requested IPv6 raw work never falls back to another transport.


## Phase 16 — production dual-stack completion

Phase 16 completes the safe dual-stack integration within the same architecture. Scoped IPv6 identity is carried as binary address bytes plus optional validated zone text through target resolution, Host values, probe submissions, correlation, Connect/service socket construction, and output formatting. Numeric zones are checked as nonzero interface indices; named zones are resolved with `if_nametoindex`; no caller path strips a zone or invents an interface.

The target and packet hardening boundaries are explicit. Target and hostname expansion are rejected above documented hard ceilings. TCP and UDP receive checksums are validated for both address families, with zero IPv4 UDP checksum accepted as the IPv4 exception and zero IPv6 UDP checksum rejected. ICMPv6 error quotes are parsed through one bounded packet-layer IPv6/extension/UDP helper and correlated by exact family, binary source/destination identity, and ports before the existing UDP scheduler classifies the evidence.

`skan interfaces` reports typed IPv6 addresses, link-local zones, and separate IPv6 capture/injection capability fields. The local service fixture exercises AF_INET6 `::1` HTTP-like and SSH-like banners when available. Offline discovery, UDP, SYN construction, mixed-family orchestration, fuzz entry points, and 10,000-host IPv6/mixed scheduler tests remain on the existing recording/injected seams.

The Linux raw adapter boundary remains intentionally narrow. Raw IPv6 discovery, TCP SYN, and UDP transmission are not claimed because complete source selection, Ethernet neighbor resolution, and capture/injection behavior are not implemented as one coherent capability. Complete Neighbor Discovery and IPv6 OS fingerprinting also remain unavailable. Selecting a Linux raw path for IPv6 returns an explicit capability error; it never falls back to Connect, offline mode, or an implicitly selected interface. This keeps the implementation capability-honest while leaving the shared transport, capture, correlation, and orchestrator seams reusable for a future explicitly scoped extension.


## Phase 17 — native IPv6 adapter completion

Phase 17 keeps the packet, capture, scheduler, timer, and orchestrator topology singular while extending the existing Linux discovery, TCP SYN, UDP, and OS-probe adapters with typed IPv6 branches. The adapters select local addresses only from the explicitly configured interface, preserve IPv6 scope zones in correlation and output, compose Ethernet+IPv6 frames through `packet::Packet`, and dispatch captured TCP/UDP/ICMPv6 observations through the existing `PacketReceiver` and pending maps.

IPv6 OS probes now use the same probe families and matcher evidence path as IPv4. IPv6 TCP responses are correlated by exact binary addresses, ports, and SYN/ACK or RST identity; ICMPv6 Echo and Destination Unreachable responses are correlated by exact identifiers or bounded quoted IPv6/UDP identity. IPv6 evidence is never mixed with IPv4 evidence and no result is inferred from local platform, service, or port metadata.

The ICMPv6 model now strictly validates and serializes bounded Neighbor Solicitation/Advertisement targets, Source/Target Link-Layer Address options, solicited-node multicast addresses, and Ethernet multicast mappings. These are reusable packet primitives and deterministic tests, not an implicit automatic neighbor-resolution service: non-loopback raw IPv6 transmission still requires an explicit destination MAC or externally supplied neighbor path, and unavailable resolution is reported rather than guessed. OS observations are explicitly family-tagged; mixed evidence is rejected and the current project-owned fingerprint database remains IPv4-only, so IPv6 evidence cannot match an incompatible IPv4 record. There is no implicit interface selection, Connect fallback, offline fallback, polling, sleep, worker thread, evasion, spoofing, or public-target traffic.

## Phase 18 — production IPv6 OS fingerprinting
Phase 18 extends the existing OS subsystem rather than creating a parallel detector. The bounded database loader accepts the legacy IPv4 format and explicit IPv6 family metadata, stable IDs, specificity, and strict size/record/signature limits. The built-in database is the deterministic combination of the project-owned IPv4 and IPv6 datasets; explicit file paths remain available for isolated validation.

Every TCP, UDP, ICMPv4, and ICMPv6 observation carries explicit protocol and address-family metadata. Aggregation marks mixed families as `Unknown`, and the matcher rejects unknown/mixed evidence or incompatible fingerprint records before scoring. Match ordering is deterministic by confidence, specificity, display name, and stable fingerprint ID. Result and output models carry the selected family and stable fingerprint ID, and the report builder preserves the same ordering when attaching results to hosts.

IPv6 OS probe construction, assessment, capture correlation, and scheduling remain on the existing `OSProbe`, `OSProbeTransport`, `OSScheduler`, `OSDetector`, Linux capture, PacketReceiver, and IOEngine paths. IPv6 TCP, UDP, and ICMPv6 response identity is checked using typed binary addresses and protocol-specific correlation fields. The raw adapter reports explicit unavailable or permission-denied state when AF_PACKET or interface-local neighbor capability is absent; it never falls back to Connect, IPv4, offline mode, or implicit interface selection.

The architecture continues to exclude additional reactors, schedulers, threads, polling, sleeps, duplicate packet models, evasion, spoofing, poisoning, exploitation, credentials, persistence, stealth, and public-target traffic. The IPv6 database records are generic project-owned laboratory profiles and are not presented as authoritative OS identification.

## Phase 19 production network capability completion

Phase 19 strengthens the existing interface and transport boundaries without creating a parallel subsystem. `NetworkInterface` retains the legacy boolean fields for compatibility and now also carries typed `CapabilityFact` values. Each fact reports `AVAILABLE`, `UNAVAILABLE`, or `UNKNOWN`, the explicit interface, address family, human-readable reason, and optional system diagnostic. Facts are derived from safe AF_INET/AF_INET6 socket probes, route-table evidence, assigned source addresses, and an AF_PACKET bind probe; a syscall’s existence alone is not treated as live packet capability.

IPv4 and IPv6 derived facts cover source selection, route presence, raw capture and injection, TCP SYN, UDP, ICMP/ICMPv6, and local-link NDP prerequisites. The CLI’s existing `interfaces` command exposes these facts in stable normal and JSON forms while preserving the previous summary booleans. Explicit transport selection remains mandatory: offline uses recording transports, Connect uses nonblocking stream sockets where applicable, and Linux raw mode requires an explicit interface and returns a non-zero capability failure when the requested operation cannot open.

The existing `LinuxDiscoveryTransport` now has a bounded interface-local Neighbor Discovery cache. Validated Neighbor Advertisements must match the pending scoped target, IPv6 source/target identity, Ethernet source, and Target Link-Layer Address before the original probe is retried. The cache is limited to 64 entries, expires entries after 30 seconds, evicts deterministically, and is cleared on teardown. Solicited-node multicast, hop limit 255, SLLA/TLLA validation, duplicate handling, late timers, and cancellation remain on the same adapter, IOEngine, capture, and PacketReceiver path. IPv6 never uses ARP.

Explicit Linux IPv6 discovery reaches this adapter after target scope and interface validation. The raw SYN, UDP, ICMPv6, service, and OS paths continue to use their existing typed source selection, shared packet serialization, capture, exact correlation, timing, and result contracts. If AF_PACKET, route, source, or neighbor prerequisites are absent, the result is explicit `UNAVAILABLE`, `PermissionDenied`, or `RoutingUnavailable` evidence as appropriate. There is no Linux-to-Connect/offline downgrade, no IPv4-to-IPv6 substitution, no implicit interface selection, and no public-target traffic.


## Phase 20 — Production Hardening Record

Phase 20 preserves the existing Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline. The shared epoll-backed `IOEngine` remains the only reactor and the callback/timer model remains single-thread-affine. No worker threads, polling loops, sleep-based timers, second pipeline, or duplicate packet framework was introduced.

`ScanMetrics` now exposes low-cost target/probe lifecycle, retry, byte, parser/correlation, active/peak-probe, stage-duration, RTT, timeout, cancellation, and drop-rate fields. The generic `ScanGroup` updates lifecycle helpers at existing transitions. Aggregate target handling reserves capacity and deduplicates by non-owning address views. OS orchestration uses binary-search range boundaries instead of rescanning every port and service for every host.

`CorrelationTable` retains exact typed key equality and unordered O(1)-average lookup while adding deterministic deadline-indexed cleanup. Duplicate, found, missed, late, removal, and cleanup activity is observable; insertion rolls back if the expiry index cannot be allocated. Existing IOEngine timer ownership and stage cleanup remain unchanged.

Service detection is bounded and project-owned. Its grammar accepts TCP/UDP probes and exact, prefix, substring, and regex rules. The corpus adds TCP banners, TLS record-header/alert identification, and UDP DNS/NTP/SNMP/SSDP-style probes. TCP and UDP service work share one transport interface and one IOEngine; live UDP uses nonblocking datagrams and offline recording supports both protocols. TLS behavior is identification-only.

Output ordering helpers now return sorted non-owning pointer views, avoiding complete per-host port/service/OS result copies for each writer while preserving deterministic normal, JSON, XML, and grepable output. The fuzz harness covers service matching and output escaping in addition to packet, quote, target, timing, UDP, and OS paths. Capability boundaries remain explicit: AF_PACKET-dependent behavior is unavailable or unknown when unproven, and Linux mode never falls back to Connect or offline mode. Phase 20 validation uses only offline fixtures, loopback, and private documentation addresses.

## Phase 21 Architecture Record — Explicit Linux Preflight

Phase 21 preserves the existing architecture and adds no parallel scan pipeline or reactor. The reusable interface module now owns bounded, non-transmitting evidence collection for MTU, route/default-route presence, source-address presence, AF_INET/AF_INET6, Ethernet capture/injection, and family-aware preflight categories. `preflight_interface()` is called by the Linux TCP SYN, raw UDP, discovery, and OS adapters at startup and again for the target family before submission. The scheduler, packet models, `PacketReceiver`, `CorrelationTable`, timers, service scheduler, OS scheduler, and output model remain the existing subsystems.

The preflight deliberately distinguishes evidence from proof. AF_PACKET bind establishes capture capability evidence; injection remains UNKNOWN until a user-requested operation exercises the send path. No probe is transmitted during self-test. An explicit operation that lacks capture, source, route, MTU, or injection prerequisites fails with a typed category and nonzero CLI status. No Linux-to-Connect or Linux-to-offline fallback is permitted.

IPv6 discovery accepts a target-family hint before opening so loopback, global, and scoped link-local diagnostics remain family-correct. NDP remains discovery-local and bounded; Phase 21 does not claim a generalized neighbor subsystem for every raw adapter. Non-loopback raw IPv6 SYN/UDP/OS operation remains capability- and neighbor-dependent, with explicit destination-MAC/NDP limitations documented rather than hidden.

`ScanMetrics` now exposes saturating-safe target failure, cancellation, retry, SRTT, RTTVAR, RTO, and timeout-backoff fields. Writers consume the canonical report only; JSON, XML, normal, and grepable formats are still presentation branches of one output tree. No blocking operation, shell invocation, worker thread, polling loop, or sleep-based wait was introduced.


## Phase 22 Architecture Record

Phase 22 extends the existing interface module rather than adding a parallel capability subsystem. `select_interface_for_target` evaluates the already-resolved target families against deterministic interface enumeration, assigned sources, and route evidence; loopback targets receive the controlled local exception needed for `lo`. A single selected interface is propagated through the existing orchestrator and stage constructors, and explicit user selection still takes precedence.

The Linux discovery adapter now rewrites the offline-oriented ARP request with the actual selected interface MAC and IPv4 source before Ethernet transmission. ARP replies are admitted only when Ethernet and ARP identities agree with the pending target and selected local identity. IPv6 continues to use NDP only, with scoped link-local validation and the existing bounded discovery-local cache/retry path.

Phase 22 also preserves structured failure semantics through the existing transport/session boundary. TCP Connect distinguishes timeout, routed-unreachable, and unavailable-local-source errors. Raw UDP records family-aware preflight and injection diagnostics. Linux raw OS setup is a terminal capability failure when AF_PACKET or another required prerequisite is unavailable; it does not return a fabricated identity or silently substitute another transport. The single epoll reactor, one-shot timers, packet parser, correlation ownership, and canonical output model remain unchanged.


## Phase 23 architecture update

Phase 23 keeps the existing Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output flow and one epoll-based `IOEngine`. Raw SYN and discovery ICMP errors now carry exact quoted IPv4/IPv6 probe identity through the existing response seams, allowing the schedulers to finalize `UNREACHABLE` evidence without a second reactor, worker pool, or fallback transport.

Discovery host aggregation and canonical serializers preserve explicit `UNREACHABLE` state alongside UP, DOWN, and UNKNOWN. TCP SYN uses the same typed `PortResponse` contract as Connect and UDP, while `-p` and bounded `-p-` selection reuse the existing strict port parser. No authorization gate, loopback-only production restriction, hidden allowlist, or public-target automation was introduced.

Non-loopback IPv6 Ethernet destination resolution remains capability-dependent on the existing interface and neighbor mechanisms. The restricted sandbox cannot open AF_PACKET, so raw packet exchange is not represented as validated success.


## Phase 24 architecture update

Phase 24 preserves the established CLI → Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline and one `io::IOEngine` epoll reactor. No second scheduler, polling loop, worker thread, duplicate packet framework, or duplicate output model was introduced.

The live SYN adapter now performs final TCP pseudo-header checksum construction using the selected typed source and target addresses for both IPv4 and IPv6 frames. This closes a transmit-integrity gap without moving checksum ownership out of the existing packet layer or changing correlation ownership. Discovery and SYN ICMP unreachable evidence continues through typed response boundaries and the existing schedulers.

Phase 24 validation is capability-aware. Connect/service paths can be exercised on local sockets; raw capture/injection paths require Linux AF_PACKET permission, valid route/source/family facts, MTU, link state, and neighbor information. When any prerequisite is unavailable, the existing typed diagnostic is returned and no fallback is selected.


## Phase 25 architecture update

Phase 25 preserves the existing CLI → Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline and single epoll-based `io::IOEngine`. Remote target expansion, raw interface selection, source selection, packet construction, response correlation, retries, timers, metrics, cancellation, shutdown, service detection, OS matching, and serialization continue to use the existing subsystems.

The CLI now exposes explicit `connect`, `offline`, and `linux` transport names. `connect` routes to the existing nonblocking TCP transport, `offline` routes to the existing recording/injected transport, and `linux` routes to the existing AF_PACKET capture/injection adapters. This is an explicit mode distinction, not fallback behavior.

For raw SYN transmission, final TCP pseudo-header checksums are calculated during frame composition from the selected source and destination addresses. Remote Ethernet delivery still requires the existing interface, route, MTU, capture, injection, and neighbor prerequisites. ARP and IPv6 NDP remain bounded, strictly correlated, and capability-gated; unavailable prerequisites terminate the selected raw path with typed diagnostics.


## Phase 26 architecture update

Phase 26 preserves the established CLI → Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline and one epoll-based `io::IOEngine`. No worker threads, duplicate reactor, duplicate scheduler, blocking receive loop, alternate output tree, or hidden transport fallback was introduced.

Linux raw stage failures now pass through one shared orchestrator formatter that records `transport=linux`, the selected interface, address family, operation, typed preflight category, numeric `errno`, and exact system message. Status mapping remains unchanged: capability failures are terminal and are never substituted with Connect or offline behavior.

The actual environment remains responsible for validating live packet paths. Existing route/next-hop, source-address, ARP, NDP, capture, injection, checksum, correlation, timer, and teardown logic is reused; unavailable AF_PACKET permission is represented as a structured failure at the stage boundary.


## Phase 27 architecture update

Phase 27 adds no runtime architecture. The existing CLI → Target Engine → Scan Orchestrator → Discovery / Port Scan / Service Detection / OS Detection → IOEngine / packet layer → Linux transport → ScanReport / OutputManager ownership remains unchanged.

Build reliability is strengthened at the repository boundary: `make clean` now removes coverage metadata in addition to generated objects and binaries, and the CI workflow exercises the same build, test, sanitizer, coverage, fuzz, and static-security boundaries used for local validation. Runtime waits remain event-driven through the existing epoll reactor and one-shot timers.

## Phase 26 completion follow-up — VLAN-aware capture parsing

The existing `PacketReceiver` now accepts one validated 802.1Q (`0x8100`) or 802.1ad/QinQ outer tag (`0x88A8`) before IPv4 or IPv6. It records the outer tag control information in `PacketObservation::vlan_tci`, preserves the base Ethernet header unchanged, and advances the existing parser offset by exactly four bytes. Truncated tags remain `TruncatedEthernet`; a second nested VLAN tag is not recursively parsed and remains an unsupported inner EtherType. All existing transport, checksum, IPv6-extension, and correlation paths continue to consume the same canonical observation and single reactor.

This is an offline/injected parser capability. The current sandbox cannot open AF_PACKET, so no VLAN packet exchange or raw live scan is claimed as validated.

## Phase 27 architecture update

Phase 27 preserves the existing CLI → Target Engine → Scan Orchestrator → Discovery → Port Scan → Service Detection → OS Detection → Output pipeline and one epoll-based `io::IOEngine`. The bounded VLAN receive path is now regression-covered for tagged TCP, UDP, ICMP, and IPv6 frames, with exact four-byte advancement and truncated-tag rejection. The parser records one outer VLAN TCI and does not recursively expand nested tags.

The benchmark driver now measures the VLAN receive parser alongside existing IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, NDP, correlation, scheduler, detection, orchestration, and serialization workloads. This remains offline/injected validation; AF_PACKET-dependent transmit and receive behavior is still capability-dependent.


## Phase 28 parser-hardening update

Phase 28 retains the single existing pipeline and epoll reactor. `PacketReceiver` now treats every parsed IPv6 Fragment header as a typed `FragmentedIPv6` result and stops before TCP, UDP, or ICMPv6 interpretation. Skan does not perform fragment reassembly in the raw correlation path; rejecting fragmented observations prevents bytes from a non-initial fragment from being mistaken for a transport header or correlated probe. Existing limits of eight extension headers and 2,048 extension bytes remain enforced.

This decision is consistent with the project’s bounded-parser policy: malformed, unsupported, over-limit, and fragmented IPv6 inputs produce deterministic non-success statuses rather than speculative protocol results. The behavior is validated with an injected fragment fixture and remains separate from live raw capability validation.
