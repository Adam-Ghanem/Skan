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

## 🏅 Security & Quality

Skan uses automated **CI, CodeQL analysis, dependency/security checks, and secret scanning** as part of its engineering workflow.

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


## Phase 26 Status — Privileged Real-Network Validation & Hardening

Phase 26 audited and hardened the existing live path without adding a second pipeline, reactor, scheduler, packet framework, or output tree. Raw Linux failure messages now identify `transport`, `interface`, `family`, `operation`, typed `category`, numeric `errno`, and the exact human-readable system message.

The observed sandbox has `lo` and `eth0`; `eth0` carries IPv4 `169.254.0.21/30`, IPv6 link-local `fe80::fc:ff:fe00:5/64`, a default IPv4 route through `169.254.0.22`, and a reachable neighbor entry for that gateway. The process is unprivileged (`uid=1000`) and AF_PACKET capture fails with `Operation not permitted`. This is reported as a capability failure rather than converted into a raw scan result.

Real local TCP Connect validation remains available for IPv4 loopback and IPv6 `::1`. Raw IPv4/IPv6 SYN, UDP, ICMP/ICMPv6, ARP, NDP, service-over-raw, and OS-over-raw exchanges are implemented and remain explicitly selected, but are **not live-validated** in this environment because capture permission is unavailable. No packet evidence is fabricated and no public target is contacted.


## Phase 27 Status — Reliability and Reproducible CI

Phase 27 continues production hardening without changing Skan’s single pipeline or epoll reactor. The build clean target now removes coverage metadata as well as generated objects, preventing instrumented artifacts from contaminating later ordinary links. GitHub Actions now runs clean build/test, debug/release, sanitizers, coverage, fuzz capability handling, static checks, prohibited-API checks, and repository-clean verification.

The environment remains capability-honest: IPv4/IPv6 Connect and deterministic offline/injected paths are locally testable, while raw SYN, UDP, ICMP/ICMPv6, ARP, NDP, raw service, and raw OS validation remain unavailable when AF_PACKET reports `Operation not permitted`.
