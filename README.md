# Skan

Skan is an original, modular Linux network-scanning platform under development. It is inspired by general scanner engineering principles, but it does not copy other scanner source code or claim compatibility with any other scanner.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, asynchronous I/O engine, packet layer, host discovery, scan engine, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides reusable infrastructure and a scoped host-discovery engine; it does not implement port scanning or a full network-scanning workflow.

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
| Phase 4 and later | Planned |

Phase 3 is deliberately scoped to explicitly supplied, authorized targets. Its default transport is a deterministic recording transport for offline tests and safe CLI exercises. No public Internet target is used by the test suite, and no packet is transmitted by the current implementation.

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

`DiscoveryScheduler` accepts the existing `core::Target` value and its already-resolved `core::Host` values. It does not add a second target or CIDR parser. A caller must provide an `AuthorizationGate` callback; an unconfigured gate rejects discovery rather than silently allowing it. The CLI uses `AuthorizationGate::loopback_only()` and therefore accepts only IPv4 loopback addresses. Production or lab integrations must supply their own repository-approved authorization callback and transport.

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

Compile and execute all Phase 0, Phase 1, Phase 2, and Phase 3 tests with:

```sh
make test
```

The suite includes deterministic unit tests for discovery type names and IPv4 parsing; ICMP, TCP, and ARP submission and response matching; malformed and unrelated responses; authorization rejection; scheduler bounds; duplicate and late response handling; RTT; timeouts; multi-probe aggregation; multiple targets; and a controlled local integration test using loopback data and an offline recording transport. Existing Phase 0–2 tests remain active.

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

The CLI uses the explicit loopback authorization gate and the offline recording transport. It reports `UNKNOWN` when no synthetic response is injected; it does not open a raw socket or connect to the target. ARP is available to the packet/probe unit tests and future authorized lab transports, but the current loopback CLI does not claim an Ethernet interface.

Unknown or incomplete arguments print a clear error and return a non-zero status. There is no `--no-auth`, `--bypass-auth`, hidden authorization path, port range option, or service-detection option.

## Network and safety boundary

Phase 3 does not implement packet transmission. There is no raw socket, `AF_PACKET`, `sendto()`, TCP connect loop, packet injection, ARP spoofing, ARP poisoning, gratuitous ARP attack, host-range expansion, public-target default, TCP/UDP port scanning, service detection, operating-system fingerprinting, Lua scripting, evasion, or dashboard functionality. Network transport must be added later behind the explicit `DiscoveryTransport` and authorization boundaries.

Integration testing uses only loopback addresses and synthetic local byte buffers. No public Internet targets were scanned.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
