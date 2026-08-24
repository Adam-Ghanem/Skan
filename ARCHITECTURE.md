# Skan Architecture

Skan is an original Linux network-scanning platform designed as a modular C++20 application. The architecture is influenced by established scanner engineering principles, but all Skan implementations are original and the project does not claim compatibility with any other scanner.

## High-level stack

```text
Skan
│
├── Core
├── I/O Engine
├── Scan Engine
├── Packet Layer
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

## Language responsibilities

| Language | Responsibility | Phase 0 status |
| --- | --- | --- |
| C++20 | Application architecture, orchestration, scan engine, detection, data layer, output, and CLI | Foundation implemented |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented

**Phase 0 — Foundation** is implemented. It includes the C++20 core types, version and Phase 0 constants, strongly typed status handling, timestamped logging, the CLI bootstrap, a minimal C-compatible status API, the Makefile, unit tests, and documentation.

The executable supports only `--version` and `--help`. No sockets, raw sockets, `epoll`, event loop, packet structures, packet crafting, host discovery, port scanning, service detection, operating-system fingerprinting, Lua engine, evasion, or dashboard code is present.

## Planned modules

The following modules are architectural boundaries for future phases and are not implemented yet:

| Module | Planned responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Phase 0 foundation implemented |
| I/O Engine | Controlled input/output and future system integration | Planned |
| Scan Engine | Scan-job coordination and lifecycle management | Planned |
| Packet Layer | Packet representation and low-level packet operations | Planned |
| Discovery | Host and network discovery workflows | Planned |
| Port Scanning | Port-state probing and result collection | Planned |
| Detection | Service and operating-system detection | Planned |
| Data Layer | Persistence and serialization of scan results | Planned |
| Lua Scripting | Optional user-defined scripting extensions | Planned |
| Output | Human-readable and machine-readable result formats | Planned |
| Evasion | Future traffic and timing controls | Planned |
| CLI | Command parsing beyond the Phase 0 bootstrap | Phase 0 shell only |
| Dashboard | Future TypeScript/React visualization and management interface | Planned |

The boundaries will be refined as later phases are approved. Phase 0 intentionally avoids inheritance hierarchies, plugin systems, packet abstractions, networking abstractions, and complex dependency injection.
