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
Host Discovery
  ↓
Port Scan Scheduler and transports
  ↓
Future detection and discovery workflows
```

The Phase 1 I/O Engine is independent infrastructure. Phase 3 uses it through its public event-loop and timer API; it does not duplicate the reactor or create a second event loop.

## Language responsibilities

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Core, I/O engine, packet representation, discovery, future orchestration, detection, data, output, and CLI | Phase 0–3 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented phases

**Phase 0 — Foundation** provides C++20 core types, constants, strongly typed status handling, timestamped logging, the CLI bootstrap, the minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** provides a Linux-first `epoll` reactor, logical event registration and lifecycle management, bounded and continuous run modes, monotonic one-shot timers, cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup.

**Phase 2 — Packet Layer** provides offline packet representation, composition, validation, deterministic serialization, lightweight parsing, and checksums for Ethernet II, IPv4, TCP, UDP, and ICMPv4 Echo messages.

**Phase 3 — Host Discovery** provides a bounded scheduler, explicit authorization callback, common probe abstraction, ICMP Echo correlation, TCP SYN/ACK and RST evidence classification, minimal ARP request/reply representation, monotonic timeouts, RTT calculation, duplicate and late response handling, deterministic host-state aggregation, and a safe recording transport for offline tests.

**Phase 4 — Scoped TCP Port Scan** provides TCP-only port selection and results, a bounded scheduler over the Phase 1 reactor, real nonblocking IPv4 TCP Connect transport, and an offline packet-model-backed TCP SYN probe. It is authorization-gated for every host and does not implement a raw SYN transport in this build.

## Target and authorization integration

Phase 3 reuses `core::Target` and `core::Host` exactly as defined by Phase 0. The discovery scheduler accepts a target whose `resolved_hosts` have already been supplied by the caller. It does not introduce a second target parser, resolver, CIDR expander, or range syntax.

The repository inspected at the start of Phase 3 contained no separate resolver or authorization implementation. To avoid inventing a bypass path, Phase 3 introduces an explicit `AuthorizationGate` callback as a required scheduler dependency. A missing callback rejects discovery. The CLI uses the conservative `AuthorizationGate::loopback_only()` helper, which authorizes only IPv4 loopback addresses. A production or lab integration must supply the repository-approved authorization callback for its own explicit scope.

No discovery method can bypass this gate. There is no `--no-auth`, `--bypass-auth`, hidden allow-all branch, or implicit public-target policy.

## Discovery architecture

The execution model is:

```text
core::Target (already resolved and authorized)
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

ARP remains an offline representation in this phase. A future authorized lab transport may connect it to a directly reachable Ethernet interface; ARP spoofing, poisoning, gratuitous ARP attacks, and any other offensive ARP behavior are outside the architecture.

## Port-scan architecture

The Phase 4 execution model is:

```text
core::Target (already resolved)
          ↓
AuthorizationGate::authorize(target, host)
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

`TcpSynProbe` reuses `packet::TCP` to construct an offline SYN header. It accepts only a response from the authorized target with matching source/destination ports; SYN/ACK requires acknowledgment equal to the SYN sequence plus one and produces `OPEN`, while a correlated RST produces `CLOSED`. Malformed or unrelated packets do not complete pending work. `tcp_syn_network_capability_available()` is false in this build because no raw-packet transport is implemented; a future transport must be injected explicitly and capability-checked rather than silently falling back to fabricated network evidence.

Port selection accepts single values, comma-separated lists, and inclusive ranges. Values outside `1..65535`, malformed tokens, and descending ranges are rejected. The default is the small deterministic set `{22, 80, 443}`; no implicit full-port enumeration exists.

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
3. Timeout, malformed, unauthorized, invalid, unrelated, and absent evidence do not prove that a host is down; absent conclusive evidence remains `UNKNOWN`.

Phase 3 currently produces positive or unknown outcomes. It intentionally does not manufacture `DOWN` from a timeout.

## Packet Layer integration

Discovery does not duplicate protocol serialization. ICMP and TCP probe builders call the Phase 2 `ICMP` and `TCP` models. ARP is the only discovery-local wire representation because ARP was intentionally not added to the Phase 2 IP-focused packet layer. The packet layer remains responsible for byte ordering, header layout, checksums, serialization bounds, and protocol-local parsing.

## I/O Engine integration

The public discovery and port-scan APIs accept an existing `io::IOEngine&`. Probe deadlines use its monotonic timer service, and scheduler completion requests its `stop()`. The recording transports are injectable seams and do not own an event loop. The real Connect transport borrows the same reactor and owns only its socket/event lifecycle. A future SYN transport must present the same boundary and preserve authorization and single-thread-affine lifecycle rules.

## CLI boundary

The CLI retains `--version`, `--help`, and the Phase 3 discovery command. Phase 4 adds only:

```text
skan scan <ipv4-address> [--tcp-ports <single,list,range>]
          [--method <connect|syn>] [--timeout-ms <ms>]
          [--max-outstanding <n>]
```

Both commands use `AuthorizationGate::loopback_only()` and therefore accept only explicit IPv4 loopback targets. `scan --method connect` uses real nonblocking stream sockets. `scan --method syn` exits with a capability-unavailable error in this build; synthetic SYN behavior is covered through the library transport seam. There are no UDP, alternate TCP flag, service-detection, fingerprinting, evasion, range-expansion, or authorization-bypass options.

## Error model

Discovery maps invalid IPv4 input to `InvalidArgument` and `INVALID_TARGET`, missing or rejecting authorization to `PermissionDenied` and `UNAUTHORIZED_TARGET`, transport I/O failure to `IoError` and `SOCKET_FAILURE`, parser rejection to `ParseError` and `MALFORMED_RESPONSE`, timer or internal construction failures to `InternalError`, and late responses to `NotFound` without corrupting state. Port scanning maps Connect success to `OPEN/IMMEDIATE_SUCCESS`, refusal to `CLOSED/CONNECTION_REFUSED`, deadline expiry to `FILTERED/TIMEOUT`, and other local socket failures to `UNKNOWN/SOCKET_ERROR`. SYN capability absence is explicit `PermissionDenied`/`CAPABILITY_UNAVAILABLE`; malformed and unrelated synthetic responses leave pending state unchanged.

## Platform and network boundary

Phase 3 is Linux-first because Phase 1 uses Linux `epoll`, and any future ARP transport would require Linux interface capabilities. Current tests and the CLI do not require network privileges, external hosts, or public Internet access.

The repository contains no packet transmission, `AF_PACKET`, raw-socket send path, `sendto()`, TCP SYN network transport, UDP scanner, alternate TCP flag scan, service detection, OS fingerprinting, Lua, evasion, dashboard, or authorization bypass. Phase 4 does contain a scoped IPv4 TCP Connect transport and deterministic TCP port enumeration only after authorization. Future network transports must remain above the explicit `PortScanTransport` and `AuthorizationGate` boundaries.

## Module status

| Module | Responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Implemented in Phase 0 |
| I/O Engine | Linux epoll event dispatch, timers, and descriptor operations | Implemented in Phase 1 |
| Packet Layer | Ethernet, IPv4, TCP, UDP, ICMP representation, composition, checksums, serialization, and parsing | Implemented in Phase 2 |
| Host Discovery | Authorized, bounded, asynchronous ICMP/TCP/ARP probe scheduling and response aggregation | Implemented in Phase 3 |
| Scan Engine | Scan-job coordination and lifecycle management | Phase 4 scheduler implemented |
| Port Scanning | TCP port selection, Connect transport, SYN probe seam, state/result collection | Implemented in Phase 4; raw SYN transport unavailable |
| Detection | Service and operating-system detection | Planned |
| Data Layer | Persistence and serialization of scan results | Planned |
| Lua Scripting | Optional user-defined scripting extensions | Planned |
| Output | Human-readable and machine-readable result formats | Phase 3 result formatting only |
| Evasion | Future traffic and timing controls | Planned |
| CLI | Version/help bootstrap, discovery exercise, and loopback-scoped TCP Connect scan | Phase 4 minimal integration |
| Dashboard | Future TypeScript/React visualization and management interface | Planned |
