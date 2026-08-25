# Skan Next-Phase Roadmap

**Author:** Manus AI
**Status:** Phase 15 implementation complete; future work remains explicitly scoped.

## Completed Phase 15 boundary

Phase 15 established a typed binary IPv4/IPv6 target identity, bounded IPv6 literals/CIDR/ranges, synchronous A+AAAA resolution before the reactor, a strict IPv6 base-header model, bounded extension recognition, IPv6 pseudo-header checksums, ICMPv6 support within the declared message scope, family-aware packet observation/correlation, AF_INET6 Connect and TCP service detection, offline IPv6 discovery/UDP construction, canonical family-aware output, CLI support, and deterministic local/injected tests.

The implementation continues to use one `IOEngine`, one timer mechanism, the existing packet composer, existing schedulers, existing capture/receiver, the existing Target Engine, the existing orchestrator, and the existing output model. It does not add threads, polling, sleeps, implicit interface selection, fallback, evasion, exploitation, credentials, persistence, or public-target traffic.

## P1: native Linux IPv6 capability, only with a controlled design

A future phase may add native Linux IPv6 raw discovery and packet scanning through explicit-interface AF_PACKET capture/injection. Acceptance requires a separately reviewed typed transport path, IPv6 neighbor and source-selection handling, bounded extension parsing reuse, family-aware correlation, controlled loopback/private-lab fixtures, and capability tests that remain explicit when unavailable. It must never select an interface implicitly or fall back to offline or Connect mode.

A future phase may add a complete, bounded Neighbor Discovery implementation only if solicitation/advertisement state, link-local scope handling, options, timers, and malformed-input behavior are specified independently. The current Phase 15 code recognizes limited ND message forms but does not claim a complete ND stack.

## P1: IPv6 OS evidence only with real transport support

IPv6 OS fingerprinting remains unavailable with confidence zero. It may be considered only after a real IPv6 probe/capture transport and a project-owned evidence model are available. No future implementation may infer OS identity from an IPv6 address, port, service label, host platform, or other non-observed evidence.

## P2: measured correctness and protocol coverage

If synchronous hostname resolution becomes material, replace it behind the existing injectable `HostnameResolver` seam with an asynchronous implementation that preserves A+AAAA bounds, deterministic ordering, duplicate suppression, pre-reactor ownership, and clear failure semantics.

Additional TCP or UDP semantics may be considered only when they fit the existing typed models, strict correlation, bounded payload policies, shared packet composition, existing schedulers, canonical result states, and capability reporting. UDP service inference is not an implicit extension of UDP port scanning.

Report-building and serialization changes should remain measurement-driven. Any optimization must preserve canonical ordering, family fields, escaping, atomic output-file replacement, and the existing writer contracts.

## P3: larger architectural commitments

Optional scripting or extensibility would require a separate sandbox, execution budget, authorization model, cancellation contract, output model, and audit boundary. It remains deliberately out of scope.

Broader fingerprint corpora, additional protocol families, and platform backends should be introduced only with project-owned provenance, strict resource limits, deterministic tests, and an explicit safety review. Nmap’s documented breadth is a comparison reference, not a requirement to reproduce unsafe or unimplemented features.

## Non-goals

The project continues to reject evasion, spoofing, decoys, fragmentation attacks, idle scanning, exploitation, credential handling, persistence, public-target automation, implicit raw-interface selection, and any fallback that disguises missing live capability. Phase 16 is not started by this roadmap update.
