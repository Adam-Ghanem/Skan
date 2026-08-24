# Skan Architecture

Skan is an original Linux network-scanning platform designed as a modular C++20 application. The architecture is influenced by general scanner engineering principles, but all Skan implementations are original and the project does not claim compatibility with any other scanner.

## High-level stack

```text
Skan
│
├── Core
├── I/O Engine
├── Packet Layer
├── Scan Engine
├── Discovery
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
Future scan and discovery modules
```

The Phase 1 I/O Engine is an independent infrastructure layer. The Phase 2 Packet Layer does not depend on discovery, port scanning, detection, scripting, dashboards, or network transmission.

## Language responsibilities

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Core, I/O engine, packet representation, serialization, future orchestration, detection, data, output, and CLI | Phase 0, Phase 1, and Phase 2 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented phases

**Phase 0 — Foundation** provides C++20 core types, constants, strongly typed status handling, timestamped logging, the CLI bootstrap, the minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** provides a Linux-first `epoll` reactor, logical event registration and lifecycle management, bounded and continuous run modes, monotonic one-shot timers, cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup.

**Phase 2 — Packet Layer** provides offline packet representation, composition, validation, deterministic serialization, lightweight parsing, and checksums for Ethernet II, IPv4, TCP, UDP, and ICMPv4 Echo messages.

## PacketElement abstraction

`PacketElement` is the small polymorphic boundary shared by protocol elements. It exposes `serialized_size()`, span-based `serialize()`, and `validate()`. The span API makes the destination capacity explicit, while the inherited vector convenience method provides an owned result for callers that want one. Packet elements do not open descriptors, access the I/O engine, or perform network I/O.

Concrete elements are value-oriented C++20 classes:

| Element | Representation and responsibility |
| --- | --- |
| `Ethernet` | Two six-byte MAC addresses and a 16-bit EtherType. The Ethernet II header is always 14 bytes. |
| `IPv4` | A fixed 20-byte IPv4 header with version, IHL, DSCP/ECN, total length, identification, flags/fragment offset, TTL, protocol, checksum, and 32-bit addresses. IPv4 options and fragmentation behavior are intentionally outside Phase 2. |
| `TCP` | Ports, sequence and acknowledgment numbers, data offset, supported flags, window, checksum, urgent pointer, an extensible option representation, and payload bytes. |
| `UDP` | Ports, derived datagram length, checksum, and payload bytes. |
| `ICMP` | ICMPv4 Echo Request or Echo Reply, code, checksum, identifier, sequence, and arbitrary payload bytes. |

## Packet composition

`Packet` owns optional protocol layers through RAII-managed values. A valid composition requires an IPv4 layer and exactly one of TCP, UDP, or ICMP. Ethernet is optional because the IP-layer packet can be useful independently of a link-layer frame. The serializer always emits layers in this order:

```text
Ethernet (optional)
    ↓
IPv4
    ↓
TCP or UDP or ICMP
```

The packet composer validates that the IPv4 protocol field matches the selected payload protocol. During serialization it computes the IPv4 total length from the IPv4 and payload layers, recalculates the IPv4 header checksum, and calculates TCP or UDP checksums with the IPv4 pseudo-header. No packet is transmitted.

## Serialization model

All serialization is deterministic and bounds-checked. Multi-byte fields are written explicitly in big-endian/network byte order through small wire helpers; host endianness is never assumed. Each element reports the exact number of bytes it will produce, and span-based serialization returns `InvalidArgument` when the destination is too small or the element is invalid.

TCP options are encoded as MSS, Window Scale, SACK Permitted, or Timestamp options and padded to a 32-bit boundary. TCP and UDP payloads are owned by their value objects so that serialized sizes, parsing, and checksum inputs remain consistent. ICMP Echo payloads are serialized directly after the eight-byte header.

## Checksum architecture

The reusable Internet checksum implementation operates over `std::span<const std::uint8_t>`. It handles empty buffers, odd-length buffers by zero-padding the final byte, one's-complement carry folding, and final complementing. The same primitive supports:

1. IPv4 header checksums with the checksum field zeroed during calculation.
2. TCP checksums with source address, destination address, protocol 6, and TCP length in the IPv4 pseudo-header.
3. UDP checksums with source address, destination address, protocol 17, and UDP length in the IPv4 pseudo-header.
4. ICMP checksums over the complete ICMP message with its checksum field zeroed.

A generic pseudo-header checksum returns zero when verification of a complete checksummed message succeeds. The TCP and UDP element serializers map a computed zero to `0xFFFF` for the transmitted field, preserving the nonzero wire representation required for those protocols.

## Parsing model

Parsing is intentionally lightweight and protocol-local. `Ethernet::parse`, `IPv4::parse`, `TCP::parse`, `UDP::parse`, and `ICMP::parse` inspect only the supplied span, reject truncated or structurally invalid input, and never read beyond its bounds. Parsing is allocation-free for Ethernet and IPv4; TCP, UDP, and ICMP allocate only to own options or payload bytes in the returned value. There is no complete packet dissector or recursive parser in Phase 2.

IPv4 parsing requires a complete declared IPv4 length and verifies the header checksum. TCP parsing validates the data offset and supported option lengths. UDP parsing requires the declared datagram length to equal the supplied span. ICMP parsing is limited to Echo Request and Echo Reply and verifies the ICMP checksum.

## Phase 1 I/O architecture

The public `IOEngine` presents logical events and status values. Only `src/io/io_engine.cpp` includes Linux epoll headers and translates between logical `EventMask` values and native epoll masks. The current backend is:

```text
IOEngine
   │
   └── Linux epoll backend
```

The public separation leaves room for future `kqueue` or IOCP backends, but neither is implemented. Phase 1 remains single-thread-affine, owns its epoll descriptor through RAII, and borrows caller-owned events.

## Raw-socket and future-module boundary

Raw sockets, `AF_PACKET`, `sendto()`, packet injection, TCP SYN scanning, UDP scanning, host discovery, service detection, operating-system fingerprinting, Lua scripting, evasion, adaptive congestion control, dashboards, and all other Phase 3+ behavior are deliberately absent. Phase 2 generates and parses bytes entirely offline. Later transmission code must be introduced above this layer and must not be hidden inside packet element serialization or validation.

## Module status

| Module | Responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Implemented in Phase 0 |
| I/O Engine | Linux epoll event dispatch, timers, and descriptor operations | Implemented in Phase 1 |
| Packet Layer | Ethernet, IPv4, TCP, UDP, ICMP representation, composition, checksums, serialization, and parsing | Implemented in Phase 2 |
| Scan Engine | Scan-job coordination and lifecycle management | Planned |
| Discovery | Host and network discovery workflows | Planned |
| Port Scanning | Port-state probing and result collection | Planned |
| Detection | Service and operating-system detection | Planned |
| Data Layer | Persistence and serialization of scan results | Planned |
| Lua Scripting | Optional user-defined scripting extensions | Planned |
| Output | Human-readable and machine-readable result formats | Planned |
| Evasion | Future traffic and timing controls | Planned |
| CLI | Command parsing beyond the Phase 0 bootstrap | Phase 0 shell only |
| Dashboard | Future TypeScript/React visualization and management interface | Planned |
