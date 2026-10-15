# CORE-03 bound capture context

This is an incremental CORE-03 deliverable, not phase acceptance. The existing
SYN repair and its independent packet/debugger evidence remain authoritative in
`docs/CORE03_SYN_REPAIR.md`.

## Contract

Keep the existing strict parser, endpoint, TCP flag/sequence/acknowledgment and
ICMP-quote validators. Extend the reusable correlation key with typed local IP,
explicit protocol, kernel interface index and owning capture-session generation.
Both endpoint scopes remain exact identities. Every live TCP submission must
construct a fully populated key; invalid family/context must fail before send.
IPv4 SYN/ACK fast lookup must construct the same context from the bound capture
session and validated packet. IPv6, ACK/bare RST and ICMP paths must additionally
confirm their already-validated candidate still exists in the exact registry.
Do not introduce an unvalidated fallback lookup.

The production-internal `detail::resolve_tcp_response` owns the receive admission
decision. It takes a parsed observation, read-only pending state, the exact
registry and the adapter's interface/session identity, returning only an admitted
probe ID. It never delivers callbacks or changes pending state. IPv4 indexed
SYN/ACK matching remains indexed; other supported responses reject ambiguous
candidates. The adapter supplies ownership from `session_`, not injectable packet
metadata. Unit tests exercise this same resolver, including revoked registry
authority, wrong tokens/context, malformed evidence and ambiguity.

A pure `tcp_correlation_key(submission, interface_index, scan_generation)` factory
returns `optional<CorrelationKey>`; zero interface/generation, missing addresses,
mixed address families and unsupported probe types are invalid. The shared table
continues supporting legacy aggregate keys for its existing generic consumers;
that compatibility is not a wildcard in live transport keys.

## Limits and trust

Interface/session identity comes from the capture socket's owner, not packet
contents. Session generation isolates registry ownership; it does NOT prove that
an identical wire tuple was generated in the current session. Per-attempt fresh
wire identity, bounded retired-identity handling, asynchronous probe generations,
kernel arrival timestamps and live non-loopback UDPv6 are still CORE-03 gaps.
Do not invent generation values from received packet data or claim replay safety.
No new raw modes, scheduler state changes, Nmap calls, dependencies or CI waits.

## Acceptance

Registry tests must independently vary local IP, protocol, interface, session
generation and IPv6 scopes; each wrong key misses without removing the good key.
Factory tests cover both families and invalid context. Live SYN OPEN/CLOSED,
ACK and UDP checks must preserve independent truth assertions. Source build,
targeted/unit regressions and sanitizers must pass before publishing this chunk.
Review the complete diff independently; keep PR #87 draft and unmerged.
