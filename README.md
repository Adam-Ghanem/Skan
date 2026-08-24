# Skan

Skan is a C11 project foundation for a modular network-scanning tool. The project is currently in **Phase 0**, which establishes the build system, core data types, status handling, logging interface, CLI shell, and unit-test foundation.

No networking or scanning functionality is implemented yet. Future phases may add those capabilities behind the documented modular architecture.

## Requirements

A C compiler and GNU Make are required. GCC is used by default; Clang can be selected with `make CC=clang`.

## Build

Build the executable with:

```sh
make
```

The executable is written to `bin/skan`. Object files and dependency files are written below `build/` rather than the source tree.

For an unoptimized debug build, use:

```sh
make debug
```

## Tests

Compile and run the Phase 0 unit tests with:

```sh
make test
```

The tests cover status-string mappings, important version and protocol constants, and initialization invariants for the foundational core types.

## Current CLI

The only supported commands are:

```sh
./bin/skan --version
./bin/skan --help
```

`--version` prints the current version, `Skan 0.1.0`. `--help` explains the Phase 0 status and the commands currently available. Unknown or missing arguments produce an error and a non-zero exit status.

## Project status

Phase 0 is limited to project foundation work. Scanning, discovery, packet handling, service detection, evasion, scripting, and other future modules are not implemented.
