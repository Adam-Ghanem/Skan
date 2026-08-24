# Skan

Skan is an original, modular network scanning platform under development. It is inspired by the engineering principles of established scanners, but it does not copy their source code or claim compatibility with them.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, I/O engine, scan engine, packet layer, discovery, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides infrastructure only; network scanning behavior remains outside the completed phases.

## Language strategy

The primary implementation language is **C++20**. C11 is reserved for selected low-level or system-facing primitives where a C boundary provides a real benefit. The repository includes a small C status API to demonstrate that boundary without introducing networking code. Lua 5.4 is planned for a future scripting layer, and TypeScript/React is planned for a future dashboard.

Skan targets Linux. Phase 1 uses the Linux `epoll` API as its I/O backend. Future backends such as BSD `kqueue` or Windows IOCP are not implemented.

## Development status

| Phase | Status |
| --- | --- |
| Phase 0 — Foundation | **COMPLETE** |
| Phase 1 — I/O Engine | **COMPLETE** |
| Phase 2 and later | Planned |

Phase 1 adds a single-thread-affine asynchronous I/O engine with logical read, write, error, and hangup events; add/modify/remove operations; bounded `run_once()` and continuous `run()` modes; monotonic one-shot timers; cancellation; nonblocking file-descriptor support; callback lifecycle protection; and RAII cleanup of the epoll descriptor.

No TCP, UDP, ICMP, ARP, host-discovery, packet-crafting, service-detection, operating-system-fingerprinting, Lua, evasion, database, or dashboard functionality has been implemented.

## Requirements

A Linux environment with GNU Make, GCC, and G++ is required. Normal builds use C++20 and `-O2`; debug builds use `-g -O0`. The Phase 1 backend requires Linux epoll.

## Build

Build the executable with:

```sh
make
```

The executable is written to `bin/skan`. Object files, dependency files, and test binaries are written below `build/`; generated files are not placed in `src/`.

For a debug build, use:

```sh
make debug
```

## Tests

Compile and execute all Phase 0 and Phase 1 unit tests with:

```sh
make test
```

Tests use local pipes and the monotonic clock. They cover event construction and masks, callback invocation, registration state, readable and writable readiness, hangup handling, add/modify/remove, callback self-removal, removing another event, stop behavior, timer expiration, deadline handling, cancellation, multiple same-deadline timers, zero-duration timers, and empty queues.

## CLI usage

The CLI remains the Phase 0 bootstrap. The only supported commands are:

```sh
./bin/skan --version
./bin/skan --help
```

`--version` prints `Skan 0.1.0`. `--help` prints the current status and available options. Unknown or missing arguments print a clear error and return a non-zero status.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
