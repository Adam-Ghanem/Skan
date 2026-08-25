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

The Phase 1 I/O Engine is independent infrastructure. Phases 3–6 use it through its public event-loop and timer API; they do not duplicate the reactor or create a second event loop.

## Language responsibilities

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Core, I/O engine, packet representation, discovery, orchestration, detection, data, output, networking, and CLI | Phase 0–9 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented phases

**Phase 0 — Foundation** provides C++20 core types, constants, strongly typed status handling, timestamped logging, the CLI bootstrap, the minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** provides a Linux-first `epoll` reactor, logical event registration and lifecycle management, bounded and continuous run modes, monotonic one-shot timers, cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup.

**Phase 2 — Packet Layer** provides offline packet representation, composition, validation, deterministic serialization, lightweight parsing, and checksums for Ethernet II, IPv4, TCP, UDP, and ICMPv4 Echo messages.

**Phase 3 — Host Discovery** provides a bounded scheduler, common probe abstraction, ICMP Echo correlation, TCP SYN/ACK and RST evidence classification, minimal ARP request/reply representation, monotonic timeouts, RTT calculation, duplicate and late response handling, deterministic host-state aggregation, and a safe recording transport for offline tests.

**Phase 4 — Scoped TCP Port Scan** provides TCP-only port selection and results, a bounded scheduler over the Phase 1 reactor, real nonblocking IPv4 TCP Connect transport, and an offline packet-model-backed TCP SYN probe. Phase 10 adds the explicit-interface Linux SYN adapter without changing this scheduler contract.

**Phase 5 — Service Detection** provides an opt-in, TCP-only detector that consumes OPEN Phase 4 results, performs bounded nonblocking banner/probe exchanges through the same reactor, matches responses against a compact project-owned database, and emits deterministic structured `ServiceResult` values. It is complete for this bounded scope; it does not implement UDP detection, live OS fingerprinting, credential handling, or service exploitation.

**Phase 6 — OS Fingerprinting Architecture** is complete for its synthetic/injected scope. It provides typed packet evidence extraction, a small Skan-owned runtime fingerprint database, deterministic weighted available-evidence matching, and a bounded `OSScheduler`/`OSDetector` over the shared Phase 1 reactor. TCP SYN variants, closed variants, ECN concepts, ICMP Echo, and an offline UDP representation are injectable test capabilities; live raw-packet OS fingerprinting is deliberately unavailable and never fabricates an identity.

**Phase 7 — Adaptive Timing + Scan Engine** is complete for the reusable offline and opt-in scheduler scope described below.

**Phase 8 — Output + Result Serialization** is complete for the pure presentation scope described below.

**Phase 9 — Network Transport + Packet Capture** is complete for the infrastructure-only scope described below. It supplies explicit-interface Linux byte transport and bounded capture, deterministic offline seams, layered packet observation, small filtering, and a reusable correlation boundary. It does not add a scanner or traffic-evasion mechanism.

**Phase 10 — Real Network Scan Integration** is complete for the explicit Linux TCP SYN and discovery adapter scope described below. It preserves offline mode, uses one IOEngine, feeds existing scheduler callbacks, and keeps live OS fingerprinting capability-honest and unavailable where its required transport is not implemented.

## Target integration

Phase 3 reuses `core::Target` and `core::Host` exactly as defined by Phase 0. The discovery scheduler accepts a target whose `resolved_hosts` have already been supplied by the caller. It does not introduce a second target parser, resolver, CIDR expander, or range syntax. Each supplied host is validated as a dotted-decimal IPv4 address before probe construction.

Target selection and resolution are caller responsibilities. The scan pipeline performs normal argument, address, port, protocol, and transport validation before doing work; it does not add a hidden target-selection path or a public-target default.

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
| ICMP Echo | Uses Phase 2 `ICMP` Echo Request serialization. Correlation requires the exact target source address, Echo Reply type/code, deterministic identifier, and sequence. | Matching Echo Reply produces `UP` with `ICMP_ECHO_REPLY`. |
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

`TcpConnectTransport` opens `AF_INET` stream sockets with `SOCK_CLOEXEC`, sets them nonblocking, handles immediate `connect()` completion and `EINPROGRESS`, and registers a borrowed `io::Event` for writable/error/hangup readiness. Completion reads `SO_ERROR`; success is `OPEN`, `ECONNREFUSED` is `CLOSED`, other socket errors are `UNKNOWN`, and the scheduler deadline produces `FILTERED`. Every terminal path removes the event, cancels the shared timer, closes the descriptor exactly once, and discards the callback.

`TcpSynProbe` reuses `packet::TCP` to construct an offline SYN header. It accepts only a response with matching source/destination ports; SYN/ACK requires acknowledgment equal to the SYN sequence plus one and produces `OPEN`, while a correlated RST produces `CLOSED`. Malformed or unrelated packets do not complete pending work. `tcp_syn_network_capability_available()` is false in this build because no raw-packet transport is implemented; a future transport must be injected explicitly and capability-checked rather than silently falling back to fabricated network evidence.

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

The Phase 6 execution model is:

```text
Phase 4 PortResult / optional Phase 5 context
                    ↓
              OSDetector
                    ↓
              OSScheduler
                    ↓
  bounded TCP SYN variants, ECN, closed variants, ICMP Echo
                    ↓
          OSProbeTransport seam
             ↙                 ↘
 RecordingOSProbeTransport   future capability-gated transport
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

The database is a compact, Skan-owned, line-oriented laboratory dataset. It supports comments, blank lines, class metadata, typed numeric and boolean fields, TCP option ordering, response behavior, deterministic declaration ordering, duplicate rejection, missing metadata rejection, and explicit file-load status. It is not an imported broad fingerprint corpus. Both the CLI and library loader load `data/os-fingerprints.db`; no broad external fingerprint corpus or duplicate signature set is embedded in C++.

The matcher computes confidence from **available observed evidence only**. Absent, timed-out, unsupported, and otherwise unavailable fields do not lower a candidate’s score. Observed mismatches lower the score. Current weights emphasize TCP option ordering, window, MSS, and transport behavior while retaining TTL, DF, window scale, SACK, timestamps, flags, ACK/sequence behavior, response behavior, and ICMP fields. Categories are `NO_MATCH` below `0.30`, `LOW` from `0.30` to below `0.60`, `POSSIBLE` from `0.60` to below `0.85`, and `STRONG` at or above `0.85`. Top-N results sort by descending confidence and then fingerprint name.

Probe lifecycle state is explicit: `Generated`, `Sent`, `ResponseReceived`, `Timeout`, `Unsupported`, or `Malformed`. The model includes TCP SYN standard/variant/timestamp/ECN probes, closed-port variants, ICMP Echo, and an optional offline UDP-port-unreachable representation. The recording transport supports deterministic injection but intentionally does not claim a live UDP or raw-packet capability. `live_os_fingerprinting_available()` is false in this build; a live CLI request reports `UNAVAILABLE`, empty matches, and zero confidence rather than fabricating an OS identity.

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

All writers implement `OutputWriter` and stream directly to a caller-owned `std::ostream`. `OutputManager` only selects the writer. Hosts sort by canonical address, ports by number and protocol, services by associated port, and OS matches by descending confidence then ascending name. JSON preserves UTF-8 bytes and escapes quotes, backslashes, controls, and newlines. XML escapes attributes/text and sanitizes disallowed controls. Grepable output uses one fixed-field record per line and backslash-escapes quoted values; no machine format emits terminal color codes.

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

`ScanConfig` defaults are deliberately compatible with the earlier `scan` command: TCP Connect, no discovery, no service detection, no OS detection, the existing Phase 4 default ports when the port vector is empty, the Phase 7 default timing profile, bounded timeout and parallelism, normal output, and no file. Validation rejects empty or invalid targets, malformed dotted-decimal IPv4 addresses, port zero, invalid positive bounds, incompatible method/transport combinations, missing Linux interface requirements, unsupported discovery transport selections, invalid service limits, invalid timing profiles, and unusable output paths.

Offline mode uses the existing recording transports and is deterministic. Linux mode is selected explicitly and uses the Phase 10 adapters; raw capability or interface failures are surfaced as errors. There is no implicit fallback from Linux to offline. Explicit targets are the only supported scope mechanism, so Phase 11 adds no CIDR or range parser.

### Stage boundary and cancellation semantics

Each adapter translates `ScanConfig` into the existing subsystem configuration and delegates submission, callback correlation, timeout handling, bounded concurrency, and result collection to that subsystem. The pipeline does not create worker threads or a second event loop and does not poll or sleep. The active stage is retained only long enough to collect its result; cancellation destroys or cancels it through its existing lifecycle and then stops the shared session reactor.

Cancellation may occur before `run()`, between stages, or from an event sink. It is cooperative and idempotent. The pipeline stops starting later stages, closes active scheduler/transport resources through their existing cancellation paths, maps all results collected so far, and still serializes a valid partial report through `OutputManager`. In particular, a discovery timeout remains `UNKNOWN`, and an unavailable live OS transport yields a warning with no fabricated match, empty match list, and zero confidence.

### Canonical report mapping

`ScanReportBuilder` is the sole Phase 11 conversion boundary. It combines explicit target hosts, discovery results, port results, service results, and OS results into Phase 8 `output::HostResult` and `output::ScanReport` values. Host and child-result ordering is deterministic, unknown states and RTTs are retained, and derived summary counters come from the existing Phase 8 summary calculation. The pipeline never hand-builds JSON, XML, normal, or grepable output; `OutputManager` remains the only serialization boundary, and its file writer uses replacement/RAII semantics.

### Failure and capability model

A configuration failure occurs before network work and is returned as an invalid-argument status. A stage submission, transport, timer, parser, or internal construction error produces a typed pipeline error and a diagnostic event; the session enters `Failed` unless cancellation has already won the race. Late and duplicate responses remain governed by the existing schedulers and cannot corrupt pending state. Linux AF_PACKET tests may skip when the environment lacks permission; a real Linux scan instead fails clearly and never reports offline data as live evidence.

Phase 11 tests cover state and event contracts, report ordering, adapter delegation, deterministic offline execution, cancellation, multi-host sequencing, discovery response handling, service/OS stage order, and a bounded 100-host × 100-port workload. This preserves the existing Phase 0–10 tests and keeps capability-dependent raw-network tests environment-aware.

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
