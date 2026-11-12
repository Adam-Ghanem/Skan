# CORE-03 capture-context correlation increment

This increment follows the historical SYN investigation in
`CORE03_SYN_REPAIR.md`. It does not complete CORE-03 or claim Nmap parity.

## Implemented boundary

Live TCP submissions now populate an exact key with both typed endpoints,
ports, TCP sequence, TCP protocol, bound kernel interface index, and the owning
capture-session generation. Address-family and IPv6 scope identity participate
in equality and hashing. Missing/mixed-family addresses or zero interface/session
identity are rejected by the key factory. Legacy generic table users retain
default context; those defaults are not wildcards matching live keys.

`detail::resolve_tcp_response` makes the receive-admission decision for SYN,
ACK, bare RST and ICMP/ICMPv6 quotes. It retains the strict existing parser,
endpoint, TCP sequence/ACK/flags and quoted-packet validators. Every admitted
candidate must also have current interface/session ownership and an exact
registry entry with the correct probe token. Ambiguous candidates are rejected.
IPv4 SYN/ACK lookup remains indexed and never falls back after a contextual miss.

The resolver does not deliver callbacks or modify pending state. The Linux
adapter alone supplies live ownership from its bound session, preserves validated
wire bytes, restores response scope, and delivers admitted evidence. There is no
new transport-context injection API, scan mode, dependency, or Nmap invocation.

Debug-only rejection diagnostics distinguish tuple/sequence/ACK failures from
interface, scan-generation, registry lifecycle, ambiguity and parser failures.
No correlation field is silently ignored to force a passing lab result.

## Regression evidence

- Literal independent OPEN SYN/ACK and CLOSED RST/ACK frames exercise the indexed
  resolver, including wrong-context and removed-registry rejection.
- Both-family ACK and ICMP tests exercise actual production admission with absent
  registry authority, wrong interface/session, malformed/incorrect evidence and
  ambiguous bare resets. ACK tests also reject a wrong registry token. Rejection
  leaves good entries and pending work intact; resolution never invokes callbacks.
- Registry tests vary local address, protocol, interface, session and endpoint
  scopes independently, including retired-session misses and legacy-key misses.
- A separate ignored mutation build that removes registry authority checking
  fails the missing-registry receive test; the unmodified production test passes.
  Mutant source/binaries are not product artifacts and are not committed.

## Remaining CORE-03 requirements

Session generation is registry ownership, **not an on-wire replay nonce**. A
received packet cannot carry or prove that generation. Fresh per-attempt wire
identity, probe generations across asynchronous callbacks, bounded retired-identity
handling and kernel arrival timestamps remain unfinished. Non-loopback UDPv6
coverage was also missing at this increment; the follow-up below closes that
direct-neighbor lab gap. The existing receive lifecycle uses scheduler retirement, not an
unproven user-space drain timestamp as wire-arrival time. Historical live SYN
failure evidence remains visible in the earlier investigation document.

Full-phase acceptance and merge remain pending independent final-head validation.
GitHub CI is asynchronous; no waiting or polling is part of this work.

## Local validation — 2026-10-15

- Production build and all 88 registered C++ test binaries passed. The complete
  Makefile test target also passed 213 corpus and 46 comparison tests, plus
  version, line-ending and CORE-01 lab-contract checks. The explicit command was
  `timeout -k 3s 240s make -f Makefile -j4 test check-version check-line-endings test-core-lab-contract`.
  Selecting Makefile avoids redundantly scheduling the same corpus suite through
  GNUmakefile; the corpus suite still ran in full through `test-corpus`.
- Five targeted ASan/UBSan binaries passed with leak detection and halt-on-error:
  network transport, packet receiver, correlation/filter, UDP transport and
  port scheduler. Unprivileged raw socket open subcases reported EPERM/skipped;
  the separate privileged live lab did not skip raw validation.
- The final isolated namespace smoke passed SYN OPEN/CLOSED/drop/admin-reject
  and ACK reset/drop/admin-reject for IPv4/IPv6, connect IPv4, and UDP IPv4
  response/port-unreachable. Independent packet capture and listener/firewall
  snapshots are retained locally under `validation_runs/core03-resolver-oct15/`
  and are not committed. Non-loopback UDPv6 is not covered by this smoke.
- A final debug SYN OPEN/CLOSED run passed with submission/key, sent packet,
  parser, lookup, admission and scheduler evidence visible. It explicitly reports
  `probe-generation=not-implemented` rather than inventing protection.
- CLI compatibility, terminal output policy, six ACK-option tests, four ACK-lab
  contract tests, eight workflow/security tests and workflow-policy validation
  passed. Diff whitespace and a limited private-key/token-pattern scan passed;
  this is not a claim that a comprehensive secret-scanning service ran.
- Earlier full-suite (360s), build/sanitizer and combined CLI attempts hit bounded
  timeouts. They were not counted as passes. Incremental builds and separated
  final checks above completed successfully without relaxing assertions.
- Independent read-only review approved the implementation subject to these
  verification gates. Its Important admission-boundary test gap was fixed and
  the registry-guard deletion mutation was caught. A remaining nonblocking
  improvement is independent assertions for every legacy scalar projected by
  the factory for both probe types.

## Follow-up: directly reachable UDPv6

The UDP adapter now reuses the TCP adapter's exact-interface/address kernel
neighbor-cache lookup. Explicit destination-MAC and loopback paths are unchanged;
an absent/unusable neighbor is still a capability failure. The shared netlink
lookup has RAII descriptor ownership, aligned/bounded message parsing, a receive
timeout, a monotonic admission budget and a batch cap. It emits no NDP probes and
does not guess an off-link gateway. Its scheduling/timing limit is documented in
`CORE_GROUND_TRUTH_LAB.md`.

The new live assertion failed before the fix with UDP scan submission failure.
With the fix, the same independently configured namespace reports IPv6 UDP echo
port 18091 OPEN/UDP_RESPONSE and no-listener port 18092
CLOSED/ICMP_PORT_UNREACHABLE. Independent tcpdump shows valid-checksum IPv6 UDP
request/echo traffic and an ICMPv6 port-unreachable quoting port 18092. Artifacts
are local under `validation_runs/core03-udp6-green/`, not repository runtime data.
Existing dual-stack SYN/ACK, connect and UDPv4 smoke assertions also passed.
This is not full NDP, arbitrary IPv6 routing, loss-resilience or UDP generation
acceptance; those capabilities are not inferred from this clean lab.

The follow-up's production build, live dual-stack smoke, 88 C++ binaries,
213 corpus tests and 46 comparison tests passed. Five targeted ASan/UBSan
executions passed using Linux-temporary linked binaries to avoid mounted-volume
linker stalls. Sanitizers first caught a too-long scope-name test fixture being
dereferenced after failed parsing; the fixture was corrected and explicitly
asserts parse success. The final normal UDP target was rebuilt/run after that
fixture-only change. Production scope validation was not relaxed. Timeout and
test-failure history is recorded in the follow-up plan rather than hidden.
