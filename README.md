# Skan

Skan is an original, modular network scanning platform under development. It is inspired by the engineering principles of established scanners, but it does not copy their source code or claim compatibility with them.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, I/O engine, scan engine, packet layer, discovery, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. Networking and scanning behavior are deliberately outside the current phase.

## Language strategy

The primary implementation language is **C++20**. C11 is reserved for selected low-level or system-facing primitives where a C boundary provides a real benefit. The Phase 0 repository includes a small C status API to demonstrate that boundary without introducing networking code. Lua 5.4 is planned for a future scripting layer, and TypeScript/React is planned for a future dashboard.

Skan targets Linux. Future system integrations may use Linux APIs such as sockets, raw sockets, and `epoll`, but none of those are implemented in Phase 0.

## Current status

The project is in **Phase 0 — Foundation**. Implemented work includes the C++20 build system, foundational types, constants, status/error handling, logging, CLI bootstrap, C compatibility boundary, unit-test infrastructure, and project documentation.

No scanning, networking, packet crafting, discovery, service detection, fingerprinting, scripting engine, evasion, or dashboard functionality exists yet.

## Requirements

A Linux environment with GNU Make, GCC, and G++ is required. Normal builds use `-O2`; debug builds use `-g -O0`. The Makefile can be adapted to Clang with command-line compiler overrides.

## Build

Build the executable with:

```sh
make
```

The executable is written to `bin/skan`. Object files and dependency files are written below `build/`; generated files are not placed in `src/`.

For a debug build, use:

```sh
make debug
```

## Tests

Compile and execute the Phase 0 unit tests with:

```sh
make test
```

The tests cover C++ status conversion, the C status boundary, version and protocol constants, and basic `Host`, `Port`, `Target`, and `ScanResult` construction and invariants.

## CLI usage

The only supported commands are:

```sh
./bin/skan --version
./bin/skan --help
```

`--version` prints `Skan 0.1.0`. `--help` prints the current Phase 0 status and the available options. Unknown or missing arguments print a clear error and return a non-zero status.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
