# Phase 34: TCP ACK Scan Design

## Scope

Phase 34 adds one advanced, defensive scan family: TCP ACK firewall mapping. The CLI accepts `-sA` and `--method ack`. It reports only whether a port is `UNFILTERED` or `FILTERED`; it never treats an ACK scan as evidence that a port is open or closed.

This is intentionally a single vertical slice. FIN, NULL, Xmas, Maimon, Window, idle, decoy, spoofing, fragmentation, source-port manipulation, SCTP, IP-protocol, proxy, and payload-fuzzing scans are not part of this phase.

## Architecture

`TcpAckProbe` will be a new first-party port-scan probe alongside `TcpSynProbe`. It owns deterministic ACK packet construction and response classification. The existing `PortScanScheduler`, `LinuxNetworkScanTransport`, packet receiver, timer, correlation table, and result writers remain the only execution path; no secondary reactor, transport, thread, or shell invocation is added.

The raw Linux transport will support exactly `TcpSyn` and `TcpAck`. It will retain strict address, port, family, submission, and quoted-packet correlation. A correctly correlated TCP RST completes an ACK submission as `UNFILTERED` with `ACK_RST`; a deadline timeout completes it as `FILTERED` with `ACK_TIMEOUT`. SYN/ACK, malformed frames, wrong endpoints, wrong sequence evidence, duplicates, late replies, and unmatched ICMP quotations must not complete a pending ACK submission.

## Transport and privilege policy

`-sA` chooses the existing Linux raw transport by default and retains its existing capability-honest failures. `-sA --transport connect` is rejected before scanning. `-sA --transport offline` is an explicit deterministic simulation for unit and CLI regression only; it is not a fallback from raw transport and must be described as simulated output. No mode silently changes transport after an error.

Raw operation continues to require the operating system capabilities, route/source/interface evidence, and neighbor prerequisites that the Linux transport reports. The package stays non-SUID and does not assign capabilities automatically. CI uses only the existing isolated network namespace and documentation addresses.

## Result and downstream policy

The existing `PortState::Unfiltered` and canonical writers are reused. Normal, JSON, XML, and grepable output expose the stable probe and reason names. `--open` excludes `UNFILTERED`, because it is not an open-port result. Phase 34 rejects `-sA` with service or OS detection rather than implying that an ACK result can be fingerprinted.

## Validation

Tests first prove ACK packet fields and correlation, timeout classification, scheduler selection, config rejection, explicit offline behavior, canonical writer output, and private-lab IPv4/IPv6 RST evidence. Existing Connect, SYN, UDP, discovery, service, and OS behavior remain regression-tested. The current restricted local environment may skip AF_PACKET live tests with their existing structured diagnostics; the isolated CI namespace is the live acceptance environment.

## Non-goals and safety boundary

Skan continues to require an operator to select authorized targets. It preserves target bounds, rate controls, structured capability errors, terminal/machine text sanitization, and the no-public-target CI rule. This phase adds no target authorization bypass, evasion, stealth, exploitation, credential handling, persistence, arbitrary scripting, or background scanning.
