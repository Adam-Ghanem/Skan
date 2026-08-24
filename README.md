# Skan

Skan is an original, modular Linux network-scanning platform under development. It is inspired by general scanner engineering principles, but it does not copy other scanner source code or claim compatibility with any other scanner.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, asynchronous I/O engine, packet layer, scan engine, discovery, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides reusable infrastructure only; no scanning workflow or network transmission has been implemented.

## Language strategy

The primary implementation language is **C++20**. C11 is reserved for selected low-level or system-facing primitives where a C boundary provides a real benefit. The repository includes a small C status API to demonstrate that boundary without introducing networking code. Lua 5.4 and TypeScript/React remain planned future technologies.

Skan targets Linux. Phase 1 uses Linux `epoll` as its I/O backend. Future backends such as BSD `kqueue` or Windows IOCP are not implemented.

## Development status

| Phase | Status |
| --- | --- |
| Phase 0 — Foundation | **COMPLETE** |
| Phase 1 — I/O Engine | **COMPLETE** |
| Phase 2 — Packet Layer | **COMPLETE** |
| Phase 3 and later | Planned |

Phase 2 adds an offline packet foundation: a `PacketElement` abstraction, ordered packet composition, Ethernet II, IPv4, TCP, UDP, ICMPv4 Echo, a reusable Internet checksum engine, deterministic serialization, validation, and bounds-safe parsing helpers. It does not open raw sockets, send packets, perform discovery, scan ports, or implement any future scanning workflow.

## Packet Layer

The packet layer is organized below `include/packet/` and `src/packet/`. Supported elements serialize into caller-provided `std::span<std::uint8_t>` buffers and also provide an owned-vector convenience form. All multi-byte fields are written explicitly in network byte order.

| Element | Current support |
| --- | --- |
| Ethernet II | Destination/source MAC, EtherType, fixed 14-byte header, validation, parsing |
| IPv4 | Version 4, fixed 20-byte header, DSCP/ECN, length, identification, flags/fragment offset, TTL, protocol, addresses, header checksum, parsing |
| TCP | Ports, sequence/acknowledgment numbers, flags, window, checksum, urgent pointer, MSS/window-scale/SACK-permitted/timestamp options, payload, IPv4 pseudo-header checksum, parsing |
| UDP | Ports, derived length, payload, IPv4 pseudo-header checksum, validation, parsing |
| ICMPv4 | Echo Request and Echo Reply, identifier, sequence, payload, checksum, parsing |
| Packet | Ethernet → IPv4 → TCP/UDP/ICMP ordering, protocol validation, automatic IPv4 total length during composition, offline serialization |

The checksum engine handles zero-length and odd-length buffers, carry folding, one's-complement reduction, IPv4 header checksums, TCP/UDP IPv4 pseudo-headers, and ICMP checksums.

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

Compile and execute all Phase 0, Phase 1, and Phase 2 unit tests with:

```sh
make test
```

All tests are deterministic and offline. Packet tests cover exact Ethernet, IPv4, TCP, UDP, and ICMP serialization; protocol validation; parsing of valid messages; malformed and truncated inputs; IPv4, TCP, UDP, and ICMP checksums; TCP options; packet composition; and golden byte vectors. Existing I/O tests continue to use only local pipes, epoll, and the monotonic clock.

Sanitizer validation can be run with:

```sh
make clean
make test CXXFLAGS='-std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' CFLAGS='-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined'
```

## CLI usage

The CLI remains the Phase 0 bootstrap. The only supported commands are:

```sh
./bin/skan --version
./bin/skan --help
```

`--version` prints `Skan 0.1.0`. `--help` prints the current status and available options. Unknown or missing arguments print a clear error and return a non-zero status.

## Network and scope boundary

Phase 2 is completely testable without network privileges or external hosts. No raw socket, `AF_PACKET`, `sendto()`, packet injection, TCP SYN scan, UDP scan, host discovery, service detection, operating-system fingerprinting, Lua scripting, evasion, or dashboard functionality is present. Network transmission belongs to later phases.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
