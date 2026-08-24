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

| Language | Responsibility | Status |
| --- | --- | --- |
| C++20 | Application architecture, orchestration, I/O engine, future scan engine, detection, data layer, output, and CLI | Phase 0 and Phase 1 implemented where applicable |
| C11 | Selected low-level or system-facing primitives where a C boundary is justified | Minimal status boundary implemented |
| Lua 5.4 | Future scripting layer | Planned |
| TypeScript/React | Future dashboard | Planned |

## Implemented

**Phase 0 — Foundation** is complete. It includes C++20 core types, version and Phase 0 constants, strongly typed status handling, timestamped logging, the CLI bootstrap, a minimal C-compatible status API, the Makefile, unit tests, and documentation.

**Phase 1 — Asynchronous I/O Engine** is complete. It adds a Linux-first reactor backed by `epoll`, a logical event abstraction, descriptor registration/modification/removal, bounded and continuous run modes, monotonic one-shot timers, timer cancellation, nonblocking descriptor support, callback lifecycle protection, and RAII cleanup of the epoll descriptor.

The Phase 1 engine contains no scan logic. It does not open network sockets, discover hosts, craft packets, probe ports, identify services, or perform fingerprinting.

## Phase 1 I/O architecture

The public `IOEngine` presents logical events and status values. Only `src/io/io_engine.cpp` includes Linux epoll headers and translates between logical `EventMask` values and native epoll masks. The intended dependency direction is:

```text
Core
  ↓
IOEngine
  ↓
Future Scan Engine
  ↓
Future network modules
```

The current backend is:

```text
IOEngine
   │
   └── Linux epoll backend
```

The public separation leaves room for future `kqueue` or IOCP backends, but neither is implemented in Phase 1.

### Event model

An `Event` is a caller-owned descriptor registration containing a file descriptor, a logical mask, a callback, and an optional opaque context pointer. Logical masks support read, write, error, and hangup conditions. The callback receives the mutable logical `Event`, including its ready mask, and does not need to know about `epoll_event`.

An Event may be registered with only one `IOEngine` at a time. `IOEngine::add()` marks it registered, `modify()` changes the native interest mask, and `remove()` detaches it. The caller must keep the Event object alive while it is registered. The engine borrows the object and never deletes it.

### Event lifecycle and callback safety

Dispatch uses the native readiness snapshot only to locate candidate Event objects. Immediately before invocation, the engine verifies that the event is still registered with that engine. Consequently, if an earlier callback removes another event that is also present in the same readiness batch, the removed event is skipped.

A callback may remove itself, remove another Event, call `stop()`, or register another Event. Registration storage is not iterated directly during callback dispatch, so these operations do not invalidate the dispatch traversal. Calling `stop()` ends the current dispatch pass and causes a continuous `run()` loop to exit. `run_once()` processes one bounded iteration and resets its local stop request afterward for deterministic callers.

Callbacks are invoked inside exception guards. An exception is logged as an error and does not escape the reactor boundary or leave the engine in a running state.

### Timer model

Timers are one-shot entries stored in a map and indexed by a min-heap ordered by `std::chrono::steady_clock` deadlines. Timer identifiers are opaque integer values returned by `schedule()`. Cancellation removes the active timer from the map; stale heap entries are discarded lazily and never invoke callbacks.

The event loop calculates the nearest active timer deadline and uses the remaining duration to bound `epoll_wait()`. Deadlines use the monotonic steady clock rather than wall-clock time. Zero-duration timers are eligible during the same iteration after the wait returns, while an empty queue does not cause a busy-wait loop.

### Ownership and RAII

`IOEngine` is the owner of its epoll file descriptor and closes it in its destructor. Copying and moving the engine are disabled because it owns a live operating-system resource and borrowed registrations. Events and callbacks remain caller-owned. `shutdown()` detaches all borrowed Events, clears timers, closes the descriptor, and is idempotent.

### Thread model

Phase 1 is single-thread-affine. `IOEngine` is not advertised as thread-safe; normal operations, callbacks, event registration, and timer manipulation should occur on the event-loop thread. No worker threads, thread pool, eventfd, or signalfd infrastructure is introduced. Cross-thread wakeup can be added later as a separate feature.

## Planned modules

The following modules are architectural boundaries for future phases and are not implemented yet:

| Module | Planned responsibility | Status |
| --- | --- | --- |
| Core | Shared value types, constants, status handling, and common utilities | Implemented in Phase 0 |
| I/O Engine | Linux epoll event dispatch, timers, and descriptor operations | Implemented in Phase 1 |
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

Phase 1 intentionally avoids TCP, UDP, ICMP, and ARP scanners; raw sockets; packet crafting; service detection; operating-system fingerprinting; database parsing; Lua; scripting; evasion; dashboards; adaptive congestion control; and all other Phase 2+ functionality.
