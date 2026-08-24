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
Future Output
```

The Phase 1 I/O Engine is independent infrastructure. Phases 3–6 use it through its public event-loop and timer API; they do not duplicate the reactor or create a second event loop.

## Language responsibilities

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Core, I/O engine, packet representation, discovery, orchestration, detection, data, output, and CLI | Phase 0–5 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented phases

**Phase 0 — Foundation** provides C++20 core types, constants, strongly typed status handling, timestamped logging, the CLI bootstrap, the minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** provides a Linux-first `epoll` reactor, logical event registration and lifecycle management, bounded and continuous run modes, monotonic one-shot timers, cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup.

**Phase 2 — Packet Layer** provides offline packet representation, composition, validation, deterministic serialization, lightweight parsing, and checksums for Ethernet II, IPv4, TCP, UDP, and ICMPv4 Echo messages.

**Phase 3 — Host Discovery** provides a bounded scheduler, common probe abstraction, ICMP Echo correlation, TCP SYN/ACK and RST evidence classification, minimal ARP request/reply representation, monotonic timeouts, RTT calculation, duplicate and late response handling, deterministic host-state aggregation, and a safe recording transport for offline tests.

**Phase 4 — Scoped TCP Port Scan** provides TCP-only port selection and results, a bounded scheduler over the Phase 1 reactor, real nonblocking IPv4 TCP Connect transport, and an offline packet-model-backed TCP SYN probe. It validates each supplied IPv4 host and does not implement a raw SYN transport in this build.

**Phase 5 — Service Detection** provides an opt-in, TCP-only detector that consumes OPEN Phase 4 results, performs bounded nonblocking banner/probe exchanges through the same reactor, matches responses against a compact project-owned database, and emits deterministic structured `ServiceResult` values. It is complete for this bounded scope; it does not implement UDP detection, live OS fingerprinting, credential handling, or service exploitation.

**Phase 6 — OS Fingerprinting Architecture** is complete for its synthetic/injected scope. It provides typed packet evidence extraction, a small Skan-owned runtime fingerprint database, deterministic weighted available-evidence matching, and a bounded `OSScheduler`/`OSDetector` over the shared Phase 1 reactor. TCP SYN variants, closed variants, ECN concepts, ICMP Echo, and an offline UDP representation are injectable test capabilities; live raw-packet OS fingerprinting is deliberately unavailable and never fabricates an identity.

**Phase 7 — Adaptive Timing + Scan Engine** is complete for the reusable offline and opt-in scheduler scope described below.

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

The public discovery, port-scan, service-detection, and OS-detection APIs accept an existing `io::IOEngine&`. Probe deadlines use its monotonic timer service, and scheduler completion requests its `stop()`. The recording transports are injectable seams and do not own an event loop. The real Connect transports borrow the same reactor and own only their socket/event lifecycles. All schedulers remain single-thread-affine like the reactor.

## CLI boundary

The CLI retains `--version`, `--help`, and the Phase 3 discovery command. Phase 4 adds the scoped TCP scan, Phase 5 adds opt-in service detection, and Phase 6 adds the capability-honest OS detection command:

```text
  skan scan <ipv4-address> [--tcp-ports <single,list,range>]
          [--method <connect|syn>] [--timeout-ms <ms>]
          [--max-outstanding <n>] [--service-detect]
          [--service-db <path>] [--max-response-bytes <n>]
          [--max-probes <n>]
  skan os-detect <ipv4-address> [--os-db <path>]
          [--timeout-ms <ms>] [--max-outstanding <n>] [--json]

```

The scan command validates explicit IPv4 targets before running. `scan --method connect` uses real nonblocking stream sockets. `scan --method syn` exits with a capability-unavailable error in this build; synthetic SYN behavior is covered through the library transport seam. `--service-detect` runs only after the scan and only for OPEN TCP results. `os-detect` loads the project-owned database and then reports live capability unavailability in this build; its `--json` form emits structured unavailable state with empty matches and confidence `0`. There is no live UDP scanner, evasion, or range-expansion option.

## Error model

Discovery maps invalid IPv4 input to `InvalidArgument` and `INVALID_TARGET`, transport I/O failure to `IoError` and `SOCKET_FAILURE`, parser rejection to `ParseError` and `MALFORMED_RESPONSE`, timer or internal construction failures to `InternalError`, and late responses to `NotFound` without corrupting state. Port scanning maps Connect success to `OPEN/IMMEDIATE_SUCCESS`, refusal to `CLOSED/CONNECTION_REFUSED`, deadline expiry to `FILTERED/TIMEOUT`, and other local socket failures to `UNKNOWN/SOCKET_ERROR`. SYN capability absence is explicit `PermissionDenied`/`CAPABILITY_UNAVAILABLE`; malformed and unrelated synthetic responses leave pending state unchanged. Service detection maps timeout, close, oversized response, malformed response, invalid target, no match, and transport failure to explicit `DetectionError` values without fabricating a service identity.

## Platform and network boundary

Phase 3 is Linux-first because Phase 1 uses Linux `epoll`, and any future ARP transport would require Linux interface capabilities. Current tests and the CLI do not require network privileges, external hosts, or public Internet access.

The repository contains no packet transmission, `AF_PACKET`, raw-socket send path, `sendto()`, TCP SYN network transport, live UDP scanner, alternate TCP flag scan, live OS fingerprint transport, Lua, evasion, dashboard, or hidden scope-control mechanism. Phase 6’s OS layer is packet-model-backed and synthetic/injected only. Phase 4 contains a scoped IPv4 TCP Connect transport and deterministic TCP port enumeration after normal target validation. Phase 5 contains only TCP stream banner/probe detection on OPEN results through `ServiceTransport`; it does not perform service exploitation, credential exchange, or Internet-wide scanning.

## Module status

| Module | Responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Implemented in Phase 0 |
| I/O Engine | Linux epoll event dispatch, timers, and descriptor operations | Implemented in Phase 1 |
| Packet Layer | Ethernet, IPv4, TCP, UDP, ICMP representation, composition, checksums, serialization, and parsing | Implemented in Phase 2 |
| Host Discovery | Bounded, asynchronous ICMP/TCP/ARP probe scheduling and response aggregation | Implemented in Phase 3 |
| Scan Engine | Scan-job coordination and lifecycle management | Phase 4 scheduler implemented |
| Port Scanning | TCP port selection, Connect transport, SYN probe seam, state/result collection | Implemented in Phase 4; raw SYN transport unavailable |
| Detection | Bounded TCP banner/probe service detection and deterministic matching | Implemented in Phase 5; OS architecture in Phase 6 |
| OS Detection | Typed evidence collection, bounded injected scheduling, reduced fingerprint database, and weighted matching | Phase 6 complete for synthetic/injected scope; live raw transport unavailable |
| Data Layer | Project-owned service and OS fingerprint databases plus future persistence and serialization | Phase 5/6 compact datasets implemented; persistence planned |
| Lua Scripting | Optional user-defined scripting extensions | Planned |
| Output | Human-readable and machine-readable result formats | Phase 3 result formatting only |
| Evasion | Future traffic and timing controls | Planned |
| CLI | Version/help bootstrap, discovery exercise, scoped TCP scan, opt-in service detection, and capability-honest os-detect | Phase 6 minimal integration complete |
| Dashboard | Future TypeScript/React visualization and management interface | Planned |
