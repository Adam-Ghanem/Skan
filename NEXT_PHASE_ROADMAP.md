# Next-Phase Roadmap

**Author:** Manus AI
**Status:** Planning only; no Phase 15 implementation was started.

## P1: preserve the current safety and capability boundary

The first priority is asynchronous hostname resolution behind the existing injectable `HostnameResolver` seam if synchronous DNS latency becomes material. The implementation should retain IPv4-only behavior, bounded A-record results, deterministic ordering, duplicate suppression, and clear resolution errors. It must not add a second reactor or background thread.

The second priority is controlled live-network validation in a private lab or loopback fixture. The existing Linux AF_PACKET transport should be exercised with an explicitly selected interface, known peers, and captured expected responses. Capability failure must remain an explicit unavailable result; it must never select offline mode implicitly.

The third priority is improving OS identification quality through a broader **project-owned** corpus and calibrated evidence. Any corpus expansion must have provenance, strict parser tests, bounded candidate work, explicit insufficient-evidence semantics, and no copied Nmap database content.

## P2: measured correctness and protocol coverage

Add direct CLI parser fuzzing and long-run cancellation/resource tests. These should cover extreme target limits, malformed combinations, repeated cancellation, timer exhaustion, output-path failures, duplicate and late responses, and memory-pressure behavior without sending public-target traffic.

Profile report building and serialization before changing data structures. Only measured avoidable copies or sorts should be optimized, and all canonical output ordering and structured OS metadata must remain stable. The current benchmark provides a baseline for target expansion, schedulers, orchestration, and JSON/XML serialization.

Consider additional TCP or UDP semantics only when they can be represented by typed models, strict correlation, bounded payloads, existing packet composition, and canonical result states. UDP service inference is not an implicit extension of UDP port scanning and should be separately specified and tested.

## P3: larger architectural commitments

IPv6 requires a coordinated design across targets, packet models, ICMPv6, Neighbor Discovery, capture, transports, discovery, OS evidence, database fields, output, and tests. It should not be started as an isolated parser or transport patch.

Optional scripting or extensibility would require a separate sandbox, execution budget, authorization model, cancellation contract, output model, and audit boundary. It is not a small Phase 15 feature and remains deliberately out of scope.

## Non-goals

The project should continue to reject evasion, spoofing, decoys, fragmentation, idle scanning, exploitation, credential handling, public-target automation, and any fallback that disguises missing live capability. Nmap’s documented breadth is a comparison reference, not a requirement to reproduce those features.
