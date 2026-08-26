# Nmap comparison sources

## Official Nmap Reference Guide
Source: https://nmap.org/book/man.html

The current Nmap reference describes host discovery, port scanning, service/version detection, OS detection, NSE, timing/performance, evasion/spoofing, and output as separate capabilities. It states that Nmap reports open, filtered, closed, unfiltered, open|filtered, and closed|filtered states, and can provide reverse DNS names, OS guesses, device types, and MAC addresses.

## Host discovery
Source: https://nmap.org/book/man-host-discovery.html

Nmap supports list scan and no-ping modes, combinations of ICMP, TCP SYN/ACK, UDP, SCTP INIT, and IP protocol probes, plus ARP/IPv6 Neighbor Discovery on local Ethernet. The default discovery set includes ICMP echo, TCP SYN, TCP ACK, and ICMP timestamp (with IPv6 differences). It also documents UDP payload use and multiple response classifications.

## Port scanning techniques
Source: https://nmap.org/book/man-port-scanning-techniques.html

Nmap documents TCP Connect, SYN, UDP, SCTP INIT/COOKIE ECHO, NULL, FIN, Xmas, ACK, Window, Maimon, custom TCP flags, idle, IP protocol, and FTP bounce scan types. It states that raw-packet techniques generally require privileges on Unix. SYN and UDP scans can be combined, and UDP uses protocol-specific payloads for common ports.

## OS detection
Source: https://nmap.org/book/man-os-detection.html

Nmap OS detection sends TCP and UDP probes and compares many response properties against an `nmap-os-db` database described there as containing more than 2,600 known fingerprints. The page describes OS/device classification, CPEs, OS-scan limits, fuzzy guesses, and configurable OS retry counts.

These sources are used only for a factual capability comparison; no Nmap code or database data is copied.

## Timing and performance
Source: https://nmap.org/book/man-performance.html

Nmap documents adaptive parallelism, min/max parallelism, dynamic RTT timeouts, retransmission limits, host timeouts, scan delays/rates, and six timing templates T0–T5. It uses host groups and bounded outstanding probes and adapts to packet loss and latency.

## Output
Source: https://nmap.org/book/man-output.html

Nmap documents interactive/normal, XML, grepable, and script-kiddie output, named-file output, append/clobber behavior, and resume support. XML is emphasized as the machine-readable extensible format; grepable output is deprecated but still available.

## Service and version detection
Source: https://nmap.org/book/man-version-detection.html

Nmap uses service and version databases with probe definitions and match expressions. The reference describes intensity levels 0–9, probe rarity, service/version/product/version/OS/device/CPE extraction, and additional RPC/SSL behavior.

## Nmap Scripting Engine
Source: https://nmap.org/book/nse.html

NSE is an embedded Lua-based scripting engine supporting discovery, advanced version detection, vulnerability and backdoor detection, and extensible scripts. Scripts run in parallel and integrate with normal and XML output. Skan intentionally does not implement an NSE-equivalent scripting subsystem in this audit.

## Phase 20 Practical Gap Closure

Phase 20 closes several practical gaps without attempting equivalence. Skan now has explicit metrics and stage timing fields, deadline-indexed correlation cleanup, reduced aggregation/output copying, protocol-aware UDP service probes, exact structured matching, bounded TLS record-header/alert identification, datagram service transport through the existing reactor, expanded parser/output/fuzz coverage, and measured 10k-host behavior.

| Nmap capability area | Phase 20 Skan status |
| --- | --- |
| Adaptive timing and large-workload observability | Implemented within the existing single-reactor model; metrics are emitted from the canonical report. |
| TCP service/version probes | Expanded, bounded, project-owned corpus; not Nmap database breadth. |
| UDP service probes | Implemented for a small DNS/NTP/SNMP/SSDP-style corpus through offline and nonblocking datagram paths. |
| TLS/SSL | Identification-only record-header/alert matching; no certificate or cryptographic audit. |
| Correlation and output scale | Deadline index, exact typed keys, non-owning output views, and 100k/10k stress coverage. |
| OS database and NSE | Still intentionally much smaller and no scripting engine. |
| Evasion, decoys, spoofing, exploitation | Intentionally not implemented. |

No Nmap code, probe corpus, OS database, or NSE script was copied. Phase 20 validation remains restricted to offline fixtures, loopback, and private documentation addresses.

## Phase 21 capability status update

| Nmap capability area | Phase 21 Skan status |
| --- | --- |
| Host discovery | Implemented through the existing bounded discovery scheduler; offline/injected validation passed; Linux raw capture is capability-dependent. |
| TCP Connect | Implemented and exercised only on controlled local/loopback paths. |
| TCP SYN | Implemented through the explicit Linux adapter and offline packet path; raw live validation is unavailable when AF_PACKET returns `Operation not permitted`. |
| UDP | Implemented through bounded offline and explicit Linux raw adapters with family-aware correlation; privileged live validation is unavailable in the sandbox. |
| Service detection | Implemented for a small project-owned bounded TCP/UDP corpus, including identification-only TLS record handling; not Nmap database breadth. |
| OS detection | Implemented for bounded project-owned evidence and explicit raw transport; no identity is fabricated when live evidence is unavailable. |
| IPv4/IPv6 | Typed family-safe offline/Connect paths are implemented; raw IPv6 remains interface, route, source, and neighbor capability-dependent. |
| Timing | Shared bounded timing, RTT, retransmission, and metrics paths are implemented within the existing reactor. |
| Output | Normal, JSON, XML, and grepable output share one canonical report model and deterministic ordering. |
| Scripting/NSE | Not implemented. |
| Fingerprint corpus/CPE | Small project-owned corpus only; not equivalent to Nmap’s breadth or CPE ecosystem. |
| Evasion/decoys/spoofing/exploitation | Intentionally not implemented. |

Phase 21 does not clone Nmap, import its code or databases, or claim compatibility or equivalence. The comparison is a capability-gap record only. No public-target traffic was used.

## Phase 22 capability comparison

Phase 22 improves operational correctness at the explicit live-transport boundary without attempting Nmap equivalence. Target-aware interface selection uses Skan’s existing interface facts and route/source evidence; ARP requests use the selected local identity and replies are checked against Ethernet and ARP correlation fields; Connect errors preserve unreachable and local-source distinctions; and raw Linux failures remain structured and terminal.

| Nmap capability area | Phase 22 Skan status |
| --- | --- |
| Raw interface selection | Implemented within Skan’s existing interface/capability subsystem; deterministic source and route evidence, explicit-interface override, no fallback. |
| ARP discovery identity | Implemented for the existing bounded Linux discovery adapter; sender identity is patched from the selected interface and replies are strictly validated. |
| TCP Connect states | Implemented for the existing nonblocking path, including `UNREACHABLE` and local-source `UNKNOWN` reasons. |
| Raw SYN/UDP/ICMP/ICMPv6/NDP/OS exchange | Implemented as explicit capability-gated adapters within scope; not live-validated in this sandbox because AF_PACKET returns `Operation not permitted`. |
| Service and TLS handling | Bounded project-owned probes and identification-only TLS record handling; not Nmap’s broad probe corpus or certificate analysis. |
| OS detection | Bounded project-owned evidence and matcher; raw capability failure is explicit and does not fabricate an identity. |
| NSE, broad databases, evasion, spoofing, exploitation | Intentionally not implemented. |

No Nmap source code, probe database, OS database, or scripts were copied. All validation remains offline, loopback-only, or private/documentation-address scoped, and no public target was contacted.


## Phase 23 capability comparison

Phase 23 adds typed discovery `UNREACHABLE` evidence and exact quoted IPv4/IPv6 ICMP unreachable correlation for TCP SYN and discovery probes within Skan’s existing schedulers and report model. It also adds canonical host-unreachable counts and strict `-p`/`-p-` selection compatibility. These changes improve semantic correctness but do not establish Nmap compatibility or feature parity.

| Nmap capability area | Phase 23 Skan status |
| --- | --- |
| Target input and authorization | Explicit user-supplied targets are accepted through bounded Skan parsing; no artificial authorization gate or hidden public-target workflow exists. |
| TCP SYN unreachable classification | Implemented through exact quoted IPv4/IPv6 ICMP correlation and the existing typed `PortResponse` path; raw live validation remains capability-dependent. |
| Discovery unreachable classification | Implemented through typed response evidence, scheduler aggregation, and canonical output state. |
| Port-selection compatibility | `-p`, comma/range syntax, and bounded `-p-` full-range expansion are supported through the existing parser. |
| Broad probe/database/NSE/CPE breadth | Not implemented and not claimed. |
| Evasion, decoys, spoofing, exploitation, credential handling | Intentionally not implemented. |

No Nmap source code, probe database, OS database, or scripts were copied. Validation remains offline, loopback-only, controlled-local, or documentation-address scoped; the sandbox’s AF_PACKET denial is reported as `Operation not permitted` rather than hidden behind fallback.


## Phase 24 capability comparison

Phase 24 hardens Skan’s existing explicit Linux SYN path by recalculating TCP pseudo-header checksums against the selected IPv4/IPv6 source and destination during frame composition. This improves transmit correctness but does not imply Nmap compatibility or equivalent raw-network breadth.

| Nmap capability area | Phase 24 Skan status |
| --- | --- |
| TCP Connect | Real loopback validation remains available through Skan’s existing nonblocking socket path. |
| TCP SYN/UDP/raw discovery | Existing explicit capability-gated adapters remain implemented; raw live comparison was not performed because AF_PACKET returns `Operation not permitted`. |
| IPv4/IPv6 | Typed offline and local Connect paths are covered; raw family validation remains dependent on interface, route, source, neighbor, capture, and injection capabilities. |
| Service/TLS and OS detection | Existing bounded project-owned implementations remain; no certificate exploitation, credentials, copied fingerprint data, or fabricated identity was added. |
| Nmap breadth, NSE, CPE, evasion, spoofing, exploitation | Not implemented and intentionally outside scope. |

No Nmap code, probe database, OS database, or scripts were copied. Any future comparison must use the same operator-owned target, ports, interface, transport, and family, and must be recorded separately from offline or loopback measurements.


## Phase 25 capability comparison

Phase 25 adds explicit `connect|offline|linux` transport selection for remote target workflows while preserving Skan’s independently implemented bounded packet, scheduler, correlation, service, OS, metrics, and output subsystems. The Linux SYN path retains deterministic source/interface selection, final IPv4/IPv6 pseudo-header checksums, strict response correlation, and typed unreachable evidence.

| Nmap capability area | Phase 25 Skan status |
| --- | --- |
| Remote target specifications | Bounded IPv4/IPv6 literals, CIDR, ranges, hostnames, and mixed target sets are supported by Skan’s Target Engine. |
| TCP Connect | Explicit Connect transport is now named by `--transport connect`; local IPv4/IPv6 behavior is exercised through the existing nonblocking path. |
| TCP SYN and UDP | Explicit Linux raw adapters remain available when interface, route, source, neighbor, capture, and injection capability exists; raw remote exchange was not validated in this sandbox. |
| Discovery/ARP/NDP | Existing bounded, strictly correlated typed paths remain in place; remote Ethernet validation requires an authorized capable lab. |
| Service/TLS and OS | Existing bounded project-owned implementations remain; no authentication, credential collection, certificate exploitation, copied fingerprint data, or fabricated identity was added. |
| Timing/output | Existing adaptive timing, bounded schedulers, canonical outputs, and metrics remain; offline measurements are not represented as live remote performance. |
| Nmap breadth, NSE, CPE, evasion, spoofing, exploitation | Not implemented and intentionally outside scope. |

No Nmap code, probe database, OS database, NSE script, or CPE database was copied. A direct controlled Nmap comparison was not performed because raw AF_PACKET capability was unavailable and no public target was contacted.
