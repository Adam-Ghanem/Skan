# Skan Next-Phase Roadmap

**Author:** Manus AI
**Status:** Phase 16 implementation complete; future work remains explicitly scoped and capability-gated.

## Completed Phase 16 boundary

Phase 16 completes the production-safe dual-stack boundary on top of the Phase 0–15 architecture. Typed IPv4/IPv6 identity now includes optional validated IPv6 zone metadata, strict shared parsing, deterministic scope-aware formatting, equality, ordering, hashing, and explicit numeric/name interface-index resolution. Target and hostname expansion have hard ceilings of 1,000,000 targets and 4,096 hostname results in addition to caller-selected lower limits.

The shared packet layer includes strict IPv6 base-header and bounded extension parsing, IPv4/IPv6 TCP and UDP checksum construction and receive validation, ICMPv6 checksum validation, and a bounded quoted IPv6/UDP parser for ICMPv6 error correlation. IPv4 UDP checksum zero remains accepted as the standards-defined exception; IPv6 UDP checksum zero is rejected. The existing UDP scheduler classifies only validated ICMPv6 Destination Unreachable code 4 quotes as closed evidence and keeps malformed, unsupported, unrelated, duplicate, and late observations non-conclusive.

AF_INET6 TCP Connect and TCP service detection use the existing nonblocking lifecycle and one `io::IOEngine`. Offline discovery, UDP, SYN construction, mixed-family orchestration, family-aware output, interface inventory, local IPv6 service integration, fuzz entry points, benchmarks, and deterministic 10,000-host IPv6/mixed scheduler tests reuse the existing packet, scheduler, transport, capture, correlation, and output contracts. No second scanner, reactor, scheduler, packet stack, thread, polling loop, sleep, fallback, evasion, exploitation, credential path, persistence mechanism, or public-target traffic was introduced.

## Current capability boundary

| Capability | Current status | Boundary |
| --- | --- | --- |
| IPv4/IPv6 literals, CIDR, ranges, mixed targets | Implemented | Expansion is bounded and deterministic. |
| IPv6 zone identifiers | Implemented within scope | One strict `%zone` token is preserved; live link-local use requires an explicit resolvable zone. |
| A/AAAA resolution | Implemented | Synchronous, pre-reactor, bounded, and deterministic. |
| IPv6 packet/extensions/checksums | Implemented within bounds | Supported extensions and payloads are bounded; fragments are not reassembled. |
| ICMPv6 UDP error correlation | Implemented offline/injected | Only validated quotes and supported classifications affect the existing scheduler. |
| AF_INET6 Connect and service detection | Implemented | Uses the existing event/timer lifecycle; local `::1` coverage is conditional on platform support. |
| IPv6 interface inventory | Implemented | `interfaces` reports typed addresses, zones, and family-specific capture/injection flags. |
| Linux raw IPv6 discovery/SYN/UDP | Explicitly unavailable | The current adapters remain IPv4/ARP-specific; no fallback or implicit interface selection is allowed. |
| Complete Neighbor Discovery | Explicitly unavailable | Limited message recognition is not a state machine or neighbor-resolution implementation. |
| IPv6 OS fingerprinting | Explicitly unavailable | No OS identity is inferred without reliable IPv6 evidence transport. |
| UDP service inference and broad fingerprint corpora | Not implemented | Silence and absent evidence remain explicit; no guessing is added. |

## Future work requiring a separate acceptance review

### Native Linux IPv6 raw capability

A future phase may add native IPv6 raw discovery and packet scanning only through the existing Linux transport/capture and orchestrator seams. Acceptance would require an explicit interface, a coherent source-address policy, complete Ethernet neighbor handling or an explicitly supplied destination MAC policy, bounded extension reuse, exact family-aware correlation, controlled loopback/private-lab fixtures, and capability tests for permission and topology failures. It must never select an interface implicitly, silently use Connect or offline mode, spoof source identity, fragment packets, or contact public targets.

### Bounded Neighbor Discovery

A future phase may add local-link Neighbor Discovery only after solicitation/advertisement state, link-local scope, option parsing, timers, retries, malformed-input handling, cache ownership, and cancellation are specified as one bounded design. Limited ICMPv6 Neighbor Discovery recognition in the current packet model must not be represented as complete ND capability.

### IPv6 OS evidence

IPv6 OS fingerprinting may be considered only after a reliable IPv6 probe/capture transport and project-owned evidence model exist. The matcher must use observed packet evidence only, preserve explicit `UNAVAILABLE` and zero-confidence states, and remain within the existing OS scheduler and output model. It must not infer identity from an address, port, service label, local platform, or guessed network behavior.

### Measurement and maintenance

If synchronous hostname resolution becomes a demonstrated startup bottleneck, it may be replaced behind the existing injectable `HostnameResolver` seam with bounded cancellation and deterministic A/AAAA ordering; it must not create an unreviewed worker or reactor architecture. Further packet semantics may be added only when they fit the current typed models, strict correlation, bounded payload policies, shared composition, existing schedulers, canonical result states, and capability reporting.

Any broader service or OS corpus must have project-owned provenance, deterministic parser tests, bounded memory and execution behavior, and an explicit safety review. Optional scripting would require a separate sandbox, authorization, resource budget, cancellation contract, and output model. It is not an automatic extension of scanning.

## Non-goals

Skan continues to reject evasion, spoofing, decoys, fragmentation attacks, idle scanning, exploitation, credential handling, persistence, public-target automation, implicit raw-interface selection, and any fallback that disguises missing live capability. Nmap feature breadth remains a comparison reference rather than an implementation obligation.

## Phase 18 status override
The Phase 18 record supersedes the historical current-capability table above for IPv6 OS fingerprinting. The project-owned `data/os-fingerprints-v6.db` is now loaded with the IPv4 database through the existing bounded loader, and typed TCP/UDP/ICMPv4/ICMPv6 evidence is family-filtered before deterministic matching. Normal, JSON, XML, and grepable output expose address family and stable fingerprint ID.

The live raw boundary remains explicit rather than implicit. Native IPv6 OS probing requires an explicitly selected interface, usable AF_PACKET capture/injection, valid typed source selection, and either a supplied destination MAC or a supported interface-local neighbor path. If that capability is absent, Skan returns the corresponding unavailable or permission-denied state and does not fall back to Connect, IPv4, offline mode, or implicit interface selection. Neighbor Discovery packet primitives and bounded local-link state are implemented and tested, but automatic non-loopback neighbor resolution remains dependent on the selected interface’s actual capability.

The next acceptance review should focus only on broader project-owned fingerprint coverage or additional interface-local capability validation. It must preserve the existing one-reactor pipeline and continue to exclude public-target traffic, evasion, spoofing, poisoning, exploitation, credentials, persistence, stealth, threads, polling, sleeps, and duplicate subsystems.

## Phase 19 status override

Phase 19 supersedes the historical raw-IPv6 and NDP entries above for the implemented scope. Interface inventory now reports typed per-capability `AVAILABLE`, `UNAVAILABLE`, or `UNKNOWN` facts with interface, family, reason, and diagnostic metadata. IPv4 and IPv6 route/source evidence and raw AF_PACKET bind evidence are kept distinct, and derived SYN, UDP, ICMP, ICMPv6, and NDP states are not claimed available from syscall existence alone.

The existing Linux IPv6 discovery path is explicitly selectable after interface and scope validation. Its local-link NDP cache is bounded to 64 entries with a 30-second TTL, deterministic expiry/eviction, strict NS/NA option and MAC correlation, and teardown cleanup. The raw SYN, UDP, ICMPv6, service, and OS paths retain typed addresses, shared serialization, exact correlation, and explicit failure states. Linux mode never downgrades to Connect or offline mode, IPv6 never uses ARP, and no interface is selected implicitly.

The repository has been validated offline and through local loopback/Connect paths. AF_PACKET-dependent live validation remains `CAPABILITY-DEPENDENT` in restricted environments and reports `UNAVAILABLE`/`SKIPPED` with the exact operating-system diagnostic rather than being represented as successful live traffic. The optional fuzz target remains `SKIPPED` when Clang is unavailable. Broader raw integration requires an isolated lab with usable AF_PACKET permissions and is not claimed by this sandbox result.

## Phase 20 Status Override — Production Hardening

Phase 20 is implemented in the existing single-reactor pipeline. ScanMetrics now reports lifecycle, retry, byte, parser/correlation, active/peak, stage-duration, RTT, timeout, cancellation, and drop-rate observations. Correlation cleanup is deadline-indexed and deterministic; target aggregation and OS range selection avoid repeated large rescans; output writers use non-owning ordered views. Service detection now supports bounded project-owned TCP/UDP probes, exact/prefix/substring/regex matching, TLS record-header/alert identification, and one IOEngine-routed nonblocking datagram transport. Tests cover 100k correlation entries, 10k-host output, fuzz corpus seeds, expanded service matching, and benchmark rows for hostname resolution, parsers, correlation, timers, service, OS, orchestration, and all output formats.

The implementation remains capability-honest. Offline and loopback validation passed. AF_PACKET raw paths remain unavailable in the current sandbox with `Operation not permitted`; no public target was contacted and no live raw capability is claimed. Nmap-equivalent breadth, NSE, broad databases, certificate analysis, evasion, spoofing, and exploitation remain intentionally out of scope.

## Phase 21 Status Override

Phase 21 implementation is complete in the existing architecture. The current repository has a reusable, non-transmitting explicit-interface preflight for family, source, route, MTU, capture, and injection evidence; structured Linux failures; family-correct IPv6 discovery diagnostics; saturating metrics; and semantic output parity improvements.

The remaining work is environmental rather than silently deferred in code: AF_PACKET permission and a controlled private lab are required to validate raw SYN, raw UDP, ICMP/ICMPv6, NDP, and raw OS exchange. Non-loopback IPv6 neighbor resolution is still bounded and adapter-specific, and no claim is made that raw packet paths were live-validated in the restricted sandbox. Future work must continue to use the existing reactor and packet/correlation boundaries and must not introduce public-target automation, fallback transports, threads, shell execution, evasion, or exploitation.

## Phase 22 Status

Phase 22 implements deterministic raw-interface selection from target family, source, and route evidence; explicit interface remains supported and mixed-family targets require one compatible interface. The Linux ARP adapter now patches and validates real interface source identity, TCP Connect reports routed-unreachable and local-source failures distinctly, raw UDP retains structured preflight/injection diagnostics, and raw OS capability failures are terminal and non-fallback.

The remaining validation requirement is environmental: run the existing capability-gated raw SYN, ARP, NDP, UDP, ICMP/ICMPv6, service, and OS integration tests on an explicitly authorized loopback/private lab interface with AF_PACKET permission. In the current sandbox AF_PACKET returns `Operation not permitted`, so no raw exchange is claimed as live success. No public-target traffic, evasion, spoofing, exploitation, credential handling, or persistence may be introduced in the next phase.


## Phase 23 Status

Phase 23 extends the production live-scanning boundary in the existing architecture. Typed discovery `UNREACHABLE` evidence, exact quoted IPv4/IPv6 ICMP unreachable correlation for TCP SYN and discovery, canonical host-unreachable output, and strict `-p`/`-p-` selection are implemented and covered by tests.

The remaining raw validation requirement is environmental: AF_PACKET permission and an explicitly authorized loopback/private lab are needed to exercise live packet exchange. The current sandbox returns `Operation not permitted`, so no raw live success is claimed. Future work must preserve explicit targets, capability-honest failure, one reactor, bounded resources, no fallback, no threads or shell execution, and no evasion or exploitation.


## Phase 24 Status

Phase 24 completes the source-level live-path hardening currently possible in the restricted environment. Linux TCP SYN frame composition now calculates final IPv4/IPv6 TCP pseudo-header checksums from the selected source and target. Phase 23’s typed discovery/SYN unreachable correlation, automatic interface selection, bounded NDP state, output parity, and capability-honest errors remain in the single existing pipeline.

Local TCP Connect and offline/injected paths are testable here. AF_PACKET-dependent capture and injection remain unavailable with the exact diagnostic `Operation not permitted`; controlled private-lab validation is therefore required before claiming `TESTED_LIVE` for raw SYN, UDP, ARP, NDP, ICMP/ICMPv6, service-over-raw, or raw OS paths. Future phases must preserve explicit target responsibility, one reactor, bounded resources, no fallback, and no prohibited automation or evasion.
