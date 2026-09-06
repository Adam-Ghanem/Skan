# Skan

> **A modern, modular network reconnaissance engine built from scratch in C++20.**

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Adam-Ghanem/Skan/ci.yml?label=CI" alt="CI">
  <img src="https://img.shields.io/github/license/Adam-Ghanem/Skan" alt="License">
  <img src="https://img.shields.io/github/stars/Adam-Ghanem/Skan" alt="GitHub stars">
  <img src="https://img.shields.io/github/commit-activity/m/Adam-Ghanem/Skan" alt="Commit activity">
</p>

Skan is a Linux-first network scanner designed for **performance, modularity, deterministic behavior, and explicit capabilities**.

It brings host discovery, TCP/UDP scanning, service detection, OS fingerprinting, adaptive scheduling, IPv4/IPv6 networking, and structured results together behind a clean architecture built to be understood and extended.

## Installation

### Ubuntu / Debian

Download the validated `amd64` package from the GitHub Releases page, then install it with APT:

```bash
sudo apt install ./skan_0.1.1-1_amd64.deb
skan --version
```

The package installs `skan` globally in `/usr/bin` and its project-owned runtime databases in `/usr/share/skan`. It does not depend on the repository or the current working directory.

Skan has not yet been accepted into the official Debian or Ubuntu archives, so plain `sudo apt install skan` without a downloaded package is not currently available. See [Installation](docs/INSTALLATION.md) for package verification, privilege guidance, and the repository-readiness path.

## Quick start

```bash
skan -sT -p 22,80,443 192.0.2.10
sudo skan -sS --top-ports 100 192.0.2.10
sudo skan -sU -p 53 192.0.2.10
skan -sV --top-ports 100 192.0.2.10
```

TCP connect scans normally run without root. Live SYN, UDP, and other raw-packet modes can require `sudo`; the package never installs Skan setuid and does not assign Linux capabilities automatically.

## ⚡ Highlights

- 🚀 **C++20** performance-oriented core
- 🌐 **IPv4 & IPv6** networking
- 🔎 Host discovery
- 🔌 TCP & UDP scanning
- 🧠 Service & OS detection
- 🧬 Data-driven service fingerprints with bounded TLS metadata
- ⚙️ Adaptive scan scheduling
- 🧩 Modular transport and packet architecture
- 📦 Structured JSON results
- 🐧 Linux-first raw networking
- 🛡️ Explicit capability and scope boundaries
- 🧪 Deterministic offline testing

## 🏗️ Architecture

```text
                         ┌──────────────────┐
                         │       CLI        │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │  Target Engine   │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Scan Orchestrator│
                         └────────┬─────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
       ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
       │  Discovery  │     │  Port Scan  │     │  Detection  │
       │ ICMP / ARP  │     │ TCP / UDP   │     │ Service / OS │
       └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Packet / I/O Core│
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │ Linux Transport  │
                         └──────────────────┘
```

The architecture keeps **target resolution, scheduling, protocol logic, packet construction, transport, detection, and output** separated. Each layer can be tested and evolved independently.

## 🎯 Design Principles

### Explicit over implicit

Network capabilities and live transports are selected deliberately. Unsupported capabilities remain visible instead of silently falling back.

### Modular over monolithic

Discovery, scanning, detection, transport, scheduling, and output are independent layers with clear boundaries.

### Deterministic over magical

Target ordering, probe correlation, scheduling decisions, and offline execution are designed for predictable and reproducible behavior.

### Safe by design

Targets, network operations, and live capabilities are explicitly bounded and validated before execution.

### Terminal identity

Interactive normal scans use Skan's responsive terminal UI: a branded header, width-aware port/service table, semantic state colors, and an evidence-derived completion summary. Layout is selected once from the stdout terminal width: narrow at 64–87 columns, medium at 88–119, and wide at 120 or more. Smaller, non-TTY, and `TERM=dumb` output uses deterministic ASCII plain text.

Color requires an interactive color-capable stdout and can be disabled with `--no-color` or `NO_COLOR`. Redirects, output files, JSON, XML, and grepable output never receive terminal decoration. Transient progress is written only to stderr when both stdout and stderr are interactive terminals; it reports completed event counts only, never fabricates rates, percentages, or ETA, and is disabled with `--debug` so diagnostic logs cannot collide with it. Current orchestration events are emitted in post-stage batches, so the progress line is intentionally not a live packet-rate meter.

## 🔧 Building from source

This section is for developers. Package users do not need a compiler, Make, the repository path, or knowledge of the build directory. Skan currently targets Linux and requires a C++20 compiler and GNU Make.

```bash
sudo apt-get install build-essential
make -j2
make test
sudo make install PREFIX=/usr
```

Packagers can stage the same deterministic layout without root by using `make install DESTDIR=<staging-dir> PREFIX=/usr`. See [Debian packaging](docs/DEBIAN_PACKAGING.md).

Optional validation tooling:

```bash
sudo apt-get install clang nmap
make asan
make ubsan
make coverage
make fuzz
```

## 🧭 Nmap-style usage

The native `skan scan <target>` interface remains supported. A scoped Nmap-compatible mode accepts one or more positional target specifications before, between, or after supported options:

```bash
skan -sT -p 22,80,443 127.0.0.1
sudo skan -sS -sV --top-ports 100 192.0.2.2
sudo skan -sU -p 53 --transport linux 192.0.2.2
skan -sn 192.0.2.0/24
sudo skan -sS -p 1-1024 -T4 -oA scan-result 192.0.2.2
sudo skan -sS -6 -p 22,443 --exclude 2001:db8::10 2001:db8::/120
skan -sT -p 22,80,443 --exclude-ports 80 192.0.2.10 192.0.2.11
sudo skan -sS -p 1-1024 --open --reason 192.0.2.2
```

| Nmap-style option | Skan behavior |
| --- | --- |
| `-sT` | TCP Connect scan |
| `-sS` | Capability-gated Linux SYN scan |
| `-sU` | Capability-gated Linux UDP scan |
| `-sn` / `-Pn` | Discovery-only / skip discovery |
| `-sV` / `-O` | Service/version / OS detection |
| `-T0`…`-T5` | Adaptive timing profile |
| `-4` / `-6` | IPv4-only / IPv6-only resolved targets |
| `--exclude`, `--exclude-ports` | Bounded target and active-protocol port exclusions |
| `--open`, `--reason` | Open/possibly-open rows only; port-state reasons in normal output |
| Multiple positional targets | Combined and deduplicated by the Target Engine |
| `-oN`, `-oX`, `-oG`, `-oA` | Normal, XML, grepable, or aggregate output |
| `--top-ports 1..100` | Deterministic Skan-owned common TCP corpus |

See [Nmap compatibility](docs/NMAP_COMPATIBILITY.md) for exact boundaries.
See [Service fingerprinting](docs/SERVICE_FINGERPRINTS.md) for the clean-room probe format and corpus limits.

## 🏅 Security & Quality

Skan CI enforces clean builds, the complete registered test suite, debug/release builds, ASan/LSan, UBSan, coverage, fuzz capability handling, static safety checks, Nmap-compatible and PTY terminal-policy regressions, isolated privileged dual-stack validation, Debian package policy checks, and installed-package acceptance on Debian 12 and Ubuntu 24.04.

> **Security note:** Skan is a network reconnaissance tool. Only scan systems and networks you are authorized to test.

## 🧱 Built With

- **C++20**
- Linux `epoll`
- IPv4 / IPv6 sockets and packet handling
- Project-owned protocol and detection data
- Deterministic test transports

## 📄 License

Skan is released under the **MIT License**. See [`LICENSE`](LICENSE) for the full license text.

## 🔭 Vision

Skan is evolving toward a production-grade network reconnaissance platform where **networking, scheduling, evidence, and decisions can be inspected, tested, and extended** instead of hidden behind a black box.

## 🤝 Contributing

Skan is an open-source engineering project. Contributions, experiments, ideas, and improvements are welcome.

---

<p align="center">
  <strong>Skan</strong><br>
  <em>Understand the network.</em>
</p>


## Development status

Phases 29.1–33 establish the current release baseline:

- IPv6 advertised-length truncation is classified before structural parsing, including VLAN fixtures.
- The privileged harness is authorization-gated, executable, auditable, and forced onto the explicit Linux transport.
- CI creates an isolated dual-stack network namespace, validates raw IPv4/IPv6 open and closed ports, and compares Skan with Nmap.
- Nmap-style aliases cover the implemented Connect, SYN, UDP, discovery, service, OS, timing, interface, and output capabilities.
- Phase 32 adds multiple positional targets, `-4`/`-6`, resolved target exclusions, active-protocol port exclusions, and protocol-aware `-p`/`-p-`.
- Service detection adds prioritized probes, per-probe timeouts, explicit fallbacks, soft/hard matches, a broader project-owned corpus, and bounded TLS certificate/ALPN metadata.
- Phase 33 adds `--open` and `--reason` through the canonical output context without changing scan evidence or summaries.
- The terminal-dashboard milestone adds capability detection, responsive layouts, safe display-width handling, deterministic redirected output, and truthful post-stage progress without changing scan evidence.
- The project is MIT licensed.

Skan is not a complete Nmap replacement yet. NSE, traceroute, advanced scan families, Nmap-scale fingerprint breadth, and cross-platform raw transports remain future work. The project does not silently emulate unsupported features.
