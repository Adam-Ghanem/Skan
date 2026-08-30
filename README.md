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

## 🚀 Quick Start

```bash
./bin/skan scan 192.168.1.1 \
  --tcp-ports 22,80,443 \
  --method connect
```

Service detection can be enabled when needed:

```bash
./bin/skan scan 192.168.1.1 \
  --tcp-ports 22,80,443 \
  --method connect \
  --service-detect
```

### Terminal identity

Interactive normal scans use Skan's compact terminal UI: a branded header, aligned port/service table, state colors, and a concise completion summary. ANSI colors are enabled only for an interactive terminal; redirected output and output files remain color-free. Use `--no-color` to disable terminal colors explicitly and `--debug` to opt into diagnostic engine logs. JSON, XML, and grepable formats remain decoration-free for automation.

## 🔧 Build

Skan currently targets Linux and requires a C++20 compiler and GNU Make.

```bash
sudo apt-get install build-essential
make -j2
make test
```

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
./bin/skan -sT -p 22,80,443 127.0.0.1
./bin/skan -sS -sV --top-ports 100 192.0.2.2
./bin/skan -sU -p 53 --transport linux 192.0.2.2
./bin/skan -sn 192.0.2.0/24
./bin/skan -sS -p 1-1024 -T4 -oA scan-result 192.0.2.2
./bin/skan -sS -6 -p 22,443 --exclude 2001:db8::10 2001:db8::/120
./bin/skan -sT -p 22,80,443 --exclude-ports 80 192.0.2.10 192.0.2.11
./bin/skan -sS -p 1-1024 --open --reason 192.0.2.2
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

Skan CI enforces clean builds, the complete registered test suite, debug/release builds, ASan/LSan, UBSan, coverage, fuzz capability handling, static safety checks, Nmap-compatible CLI regressions, and isolated privileged dual-stack validation.

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
- The project is MIT licensed.

Skan is not a complete Nmap replacement yet. NSE, traceroute, advanced scan families, Nmap-scale fingerprint breadth, and cross-platform raw transports remain future work. The project does not silently emulate unsupported features.
