# Skan Architecture

Skan is being developed as an original, modular C11 project. The architecture is intentionally described at a high level so that later phases can add capabilities without coupling the Phase 0 foundation to networking or scanning behavior.

## Implemented

**Phase 0 foundation** is implemented. It contains the executable entry point, version and Phase 0 constants, foundational host/target/port/protocol/result types, a unified status enum, a small timestamped logger, a Makefile, and a real unit-test foundation.

The Phase 0 executable supports only `--version` and `--help`. No network access is performed.

## Planned modules

The following modules are planned for future phases and are not implemented in Phase 0:

| Module | Planned responsibility | Phase 0 status |
| --- | --- | --- |
| Core | Shared types, constants, status handling, and common utilities | Foundation implemented |
| I/O Engine | Controlled input and output operations used by higher layers | Planned |
| Scan Engine | Coordination of scan jobs and scan lifecycle | Planned |
| Packet | Packet representation and low-level packet operations | Planned |
| Discovery | Host and network discovery workflows | Planned |
| Port Scan | Port-state probing and result collection | Planned |
| Detection | Service and operating-system detection workflows | Planned |
| Data Layer | Persistence and serialization of scan results | Planned |
| Scripting | Optional user-defined extensions | Planned |
| Output | Human-readable and machine-readable result formats | Planned |
| Evasion | Optional traffic and timing controls | Planned |
| CLI | Command parsing and user-facing operations beyond Phase 0 | Phase 0 shell only |
| Dashboard | Future visualization and management interface | Planned |

The planned modules will communicate through explicit interfaces and the shared core types. Their boundaries may be refined as implementation requirements become clearer.

## Design constraints

Phase 0 deliberately excludes sockets, packet crafting, scanning logic, host discovery, service detection, operating-system fingerprinting, scripting, and evasion. It also does not attempt to reproduce another scanner's implementation or feature set. The architecture is original and will evolve incrementally as future phases are approved.
