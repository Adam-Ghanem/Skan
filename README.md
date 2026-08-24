# Skan

Skan is an original, modular Linux network-scanning platform under development. It is inspired by general scanner engineering principles, but it does not copy other scanner source code or claim compatibility with any other scanner.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, asynchronous I/O engine, packet layer, host discovery, scan engine, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides reusable infrastructure, a scoped host-discovery engine, the Phase 4 TCP port-scan foundation, and the Phase 5 service-detection layer; it does not implement a full network-scanning workflow.

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
| Phase 6 and later | Planned |

Phase 3 is deliberately scoped to explicitly supplied targets. Its default transport is a deterministic recording transport for offline tests and safe CLI exercises. Phase 4 retains that pipeline boundary, adds real nonblocking TCP Connect only for supplied IPv4 targets, and keeps SYN network transmission capability-gated. Phase 5 consumes only OPEN TCP results, performs bounded service probes through the same pipeline boundary and Phase 1 reactor, and uses a small project-owned database. No public Internet target is used by the test suite.

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

`DiscoveryScheduler` accepts the existing `core::Target` value and its already-resolved `core::Host` values. It does not add a second target or CIDR parser. Each host is still validated as a dotted-decimal IPv4 address before probe construction. Production or lab integrations supply their own explicit target set and transport.

The scheduler supports concurrent ICMP Echo, TCP, and ARP probe strategies with a configurable maximum outstanding count. It keeps bounded work in a queue, assigns deterministic `ProbeId` values, records submission metadata, schedules one-shot deadlines on the shared Phase 1 `IOEngine`, and removes completed or expired probes from the pending map.

| Probe | Submission and evidence | Current transport status |
| --- | --- | --- |
| ICMP Echo | Reuses Phase 2 `ICMP` Echo Request serialization. Matches Echo Replies by target address, identifier, and sequence. | Offline recording transport only |
| TCP | Reuses Phase 2 `TCP` serialization for an explicit configured port. Classifies matching SYN/ACK or RST responses as positive reachability evidence. | Offline recording transport only |
| ARP | Uses a minimal discovery-local 28-byte ARP representation for IPv4 Ethernet request/reply construction and parsing. | Offline representation only; interface transmission is not implemented |

The default TCP discovery port is **80**, centralized in `kDefaultTcpDiscoveryPort`. The default timeout is **1000 ms**, and the default outstanding-work limit is **64**. These are discovery-policy defaults, not a port-scanning range; Phase 3 never enumerates ports.

## Correlation, timeout, and state policy

Every submission carries a `ProbeId`, target address, probe type, packet bytes, and protocol-specific correlation fields. ICMP uses a deterministic identifier and sequence derived from the probe ID. TCP uses a deterministic source port and sequence number and requires the response source/destination ports to match. ARP correlates the target IPv4 address, operation, and sender/target IPv4 fields.

The scheduler measures sent and received times with `std::chrono::steady_clock`. Successful responses expose RTT in milliseconds. A malformed response is recorded as evidence and completes the corresponding probe; an unrelated response is ignored without disturbing pending work. A response for an expired probe is classified as late and cannot change host state. A response for a completed probe is counted as a duplicate and cannot create another result.

Host aggregation is deterministic. Any positive response produces `UP`, even if another probe timed out. An explicit `DOWN` result would take precedence over `UNKNOWN` only when no positive evidence exists. A timeout or lack of conclusive evidence produces `UNKNOWN`; non-response is never treated as proof that a host is down.

## Phase 4 Scoped TCP Port Scan

The Phase 4 port scanner accepts already-resolved `core::Target` and `core::Host` values and validates every host before queueing any port. The CLI accepts explicit IPv4 targets; it does not add CIDR expansion or a public-target default.

Only TCP is supported. `--tcp-ports` accepts a single port, a comma-separated list, or an inclusive range such as `22,80,443,8000-8002`. Values are validated to `1..65535`, sorted, and deduplicated. With no explicit selection, the scanner uses the small default set `{22, 80, 443}` and never silently enumerates all 65535 ports.

The scheduler is bounded by `max_outstanding`, uses the shared Phase 1 `IOEngine` for epoll events and one-shot timers, and retains deterministic target/port/probe ordering. TCP Connect uses actual nonblocking IPv4 sockets and classifies immediate success or `SO_ERROR==0` as `OPEN`, `ECONNREFUSED` as `CLOSED`, and deadline expiry as `FILTERED`; other local socket failures are `UNKNOWN`. Socket events, timers, and descriptors are removed or closed on every terminal path.

The TCP SYN probe reuses the Phase 2 `packet::TCP` model for deterministic offline construction and validates source/destination addresses and ports, SYN/ACK acknowledgment correlation, and RST responses. This build intentionally reports the raw-packet network capability as unavailable; synthetic responses can still exercise the probe and scheduler through an injected transport. It does not claim a real SYN scan.

The minimal CLI is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80,443 --method connect \
  --timeout-ms 500 --max-outstanding 16
```

`--method syn` is accepted as a capability-gated mode and exits without network activity when the raw-packet capability is unavailable. UDP scanning, alternate TCP flag scans, evasion, decoys, spoofing, fragmentation tricks, OS fingerprinting, scripting, dashboards, and bypass mechanisms remain outside scope. Phase 5 service detection is opt-in and limited to bounded TCP banner/probe matching on OPEN results.

## Phase 5 Service Detection

Phase 5 is an opt-in service-detection layer that consumes only `PortResult` values whose state is `OPEN` and whose protocol is TCP. It does not rescan ports, infer service identity from port numbers alone, perform UDP probes, or run operating-system fingerprinting. The CLI performs service probes only after normal IPv4 target validation.

The detector uses the shared Phase 1 `IOEngine` for nonblocking connect, writable, readable, hangup, and timeout events. Its `ServiceScheduler` bounds active probes with `max_outstanding`, bounds each response with `max_response_bytes`, limits attempts per port with `max_probes`, and retains deterministic target/port/probe ordering. Partial TCP responses are accumulated until a matcher succeeds, the peer closes, the response limit is reached, or the shared deadline expires.

Probe definitions are project-owned and stored in `data/service-probes.db` using a compact line-oriented format. Each definition names a TCP payload and one or more prefix, substring, or regular-expression rules. Regex rules may expose numbered captures as `$1`, `$2`, and so on for product and version fields. The built-in dataset is intentionally small and covers HTTP, SSH, FTP, SMTP, a TLS greeting, and a generic banner fallback; it is not an imported Nmap database.

A `ServiceResult` retains the target, TCP port, inherited port state, detection state, service, product, version, extra text, confidence, method, probe name, optional RTT, error classification, and completion timestamp. Matching is deterministic: the highest confidence wins, followed by rule specificity and declaration order. No-match, timeout, connection-closed, oversized-response, malformed, invalid-target and transport-error outcomes remain explicit rather than being converted into guessed service identities.

The CLI extension is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --method connect \
  --timeout-ms 500 --max-outstanding 16 --service-detect \
  --max-response-bytes 8192 --max-probes 2
```

An explicit project-owned database may be selected with `--service-db data/service-probes.db`. Service detection is performed only after the port scan completes, and only OPEN TCP results enter the service scheduler. The current implementation intentionally does not claim protocol-complete identification, TLS negotiation, credential handling, service exploitation, UDP detection, OS fingerprinting, or Internet-wide scanning. Phase 5 is complete for this bounded banner/probe scope.

## Phase 2 Packet Layer

The packet layer remains below discovery and is responsible for protocol representation, validation, deterministic serialization, checksums, and lightweight parsing. Discovery does not duplicate ICMP or TCP packet construction. Packet elements continue to serialize into caller-provided `std::span<std::uint8_t>` buffers and provide owned-vector convenience forms.

| Element | Current support |
| --- | --- |
| Ethernet II | Destination/source MAC, EtherType, fixed 14-byte header, validation, parsing |
| IPv4 | Version 4, fixed 20-byte header, fields, addresses, checksum, parsing |
| TCP | Ports, sequence/acknowledgment numbers, flags, supported options, payload, IPv4 pseudo-header checksum, parsing |
| UDP | Ports, derived length, payload, IPv4 pseudo-header checksum, parsing |
| ICMPv4 | Echo Request and Echo Reply, identifier, sequence, payload, checksum, parsing |
| Packet | Ordered Ethernet → IPv4 → TCP/UDP/ICMP composition and offline serialization |

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

Compile and execute all Phase 0 through Phase 5 tests with:

```sh
make test
```

The suite includes deterministic unit tests for discovery and port-selection parsing; TCP Connect and TCP SYN probe classification; Phase 2 TCP packet reuse; service database parsing; prefix, substring, and regex matching; bounded service scheduling; partial responses; malformed, oversized, duplicate, and late responses; invalid-target handling; timeouts; retries; multiple targets; and stress-sized synthetic scans. Controlled local integration tests exercise real loopback TCP Connect and real SSH/HTTP banner detection without using public targets. Existing Phase 0–5 tests remain active.

Sanitizer validation can be run with:

```sh
make clean
make test CXXFLAGS='-std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' CFLAGS='-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined'
```

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

Unknown or incomplete arguments print a clear error and return a non-zero status. There is no hidden target-selection path, implicit public-target default, UDP option, alternate TCP flag option, or full-port-range default.

## Network and safety boundary

Phase 4 implements IPv4 TCP Connect transport through nonblocking stream sockets, and Phase 5 adds TCP banner/probe service detection on OPEN results. There is no raw packet transmission in this build: no `AF_PACKET`, `sendto()`, SYN network transport, spoofing, ARP attack behavior, host-range expansion, public-target default, UDP scanning, alternate TCP flag scanning, evasion, operating-system fingerprinting, Lua scripting, or dashboard functionality. The SYN implementation is packet-model-backed and synthetic/transport-injected only until a separately validated capability is available.

The Phase 3 integration remains offline. Phase 4 and Phase 5 integration use only `127.0.0.1` and deliberately created local listening sockets; Phase 5 additionally verifies controlled SSH and HTTP banner responses. No public Internet targets were scanned.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
