# Skan

Skan is an original, modular Linux network-scanning platform under development. It is inspired by general scanner engineering principles, but it does not copy other scanner source code or claim compatibility with any other scanner.

## Project goals

Skan is intended to grow into a serious Linux network-scanning platform with clear boundaries between the core, asynchronous I/O engine, packet layer, host discovery, scan engine, port scanning, detection, data, scripting, output, evasion, CLI, and dashboard layers. The current implementation provides reusable infrastructure, a scoped host-discovery engine, the Phase 4 TCP port-scan foundation, and the Phase 5 service-detection layer; it does not implement a full network-scanning workflow.

## Language and platform

The primary implementation language is **C++20**. C11 is reserved for selected low-level or system-facing primitives where a C boundary provides a real benefit. The repository includes a small C status API to demonstrate that boundary. Lua 5.4 and TypeScript/React remain planned future technologies.

Skan targets Linux. Phase 1 uses Linux `epoll` as its I/O backend. Phase 3 uses `std::chrono::steady_clock` deadlines and the Phase 1 timer API. Future backends such as BSD `kqueue` or Windows IOCP are not implemented.

## Development status

| Phase | Status |
| --- | --- |
| Phase 0 — Foundation | **COMPLETE** |
| Phase 1 — I/O Engine | **COMPLETE** |
| Phase 2 — Packet Layer | **COMPLETE** |
| Phase 3 — Host Discovery | **COMPLETE** |
| Phase 4 — Scoped TCP Port Scan | **COMPLETE** |
| Phase 5 — Service Detection | **COMPLETE** |
| Phase 6 — OS Fingerprinting Architecture | **COMPLETE** |
| Phase 7 — Adaptive Timing + Scan Engine | **COMPLETE** |
| Phase 8 — Output + Result Serialization | **COMPLETE** |

Phase 3 is deliberately scoped to explicitly supplied targets. Its default transport is a deterministic recording transport for offline tests and safe CLI exercises. Phase 4 retains that pipeline boundary, adds real nonblocking TCP Connect only for supplied IPv4 targets, and keeps SYN network transmission capability-gated. Phase 5 consumes only OPEN TCP results, performs bounded service probes through the same pipeline boundary and Phase 1 reactor, and uses a small project-owned database. Phase 6 adds a capability-honest OS fingerprinting architecture with injected packet-model probes and a reduced project-owned runtime database; live raw-packet OS fingerprinting remains unavailable. Phase 6 is complete for this synthetic/injected scope. No public Internet target is used by the test suite.

## Phase 3 Host Discovery

The discovery flow is:

```text
core::Target
    ↓
DiscoveryScheduler
    ↓
DiscoveryProbe
    ↓
Phase 2 packet serialization
    ↓
DiscoveryTransport
    ↓
Phase 1 IOEngine timers/event loop
    ↓
response correlation
    ↓
DiscoveryResult and HostState
```

`DiscoveryScheduler` accepts the existing `core::Target` value and its already-resolved `core::Host` values. It does not add a second target or CIDR parser. Each host is still validated as a dotted-decimal IPv4 address before probe construction. Production or lab integrations supply their own explicit target set and transport.

The scheduler supports concurrent ICMP Echo, TCP, and ARP probe strategies with a configurable maximum outstanding count. It keeps bounded work in a queue, assigns deterministic `ProbeId` values, records submission metadata, schedules one-shot deadlines on the shared Phase 1 `IOEngine`, and removes completed or expired probes from the pending map.

| Probe | Submission and evidence | Current transport status |
| --- | --- | --- |
| ICMP Echo | Reuses Phase 2 `ICMP` Echo Request serialization. Matches Echo Replies by target address, identifier, and sequence. | Offline recording transport only |
| TCP | Reuses Phase 2 `TCP` serialization for an explicit configured port. Classifies matching SYN/ACK or RST responses as positive reachability evidence. | Offline recording transport only |
| ARP | Uses a minimal discovery-local 28-byte ARP representation for IPv4 Ethernet request/reply construction and parsing. | Offline representation only; interface transmission is not implemented |

The default TCP discovery port is **80**, centralized in `kDefaultTcpDiscoveryPort`. The default timeout is **1000 ms**, and the default outstanding-work limit is **64**. These are discovery-policy defaults, not a port-scanning range; Phase 3 never enumerates ports.

## Correlation, timeout, and state policy

Every submission carries a `ProbeId`, target address, probe type, packet bytes, and protocol-specific correlation fields. ICMP uses a deterministic identifier and sequence derived from the probe ID. TCP uses a deterministic source port and sequence number and requires the response source/destination ports to match. ARP correlates the target IPv4 address, operation, and sender/target IPv4 fields.

The scheduler measures sent and received times with `std::chrono::steady_clock`. Successful responses expose RTT in milliseconds. A malformed response is recorded as evidence and completes the corresponding probe; an unrelated response is ignored without disturbing pending work. A response for an expired probe is classified as late and cannot change host state. A response for a completed probe is counted as a duplicate and cannot create another result.

Host aggregation is deterministic. Any positive response produces `UP`, even if another probe timed out. An explicit `DOWN` result would take precedence over `UNKNOWN` only when no positive evidence exists. A timeout or lack of conclusive evidence produces `UNKNOWN`; non-response is never treated as proof that a host is down.

## Phase 4 Scoped TCP Port Scan

The Phase 4 port scanner accepts already-resolved `core::Target` and `core::Host` values and validates every host before queueing any port. The CLI accepts explicit IPv4 targets; it does not add CIDR expansion or a public-target default.

Only TCP is supported. `--tcp-ports` accepts a single port, a comma-separated list, or an inclusive range such as `22,80,443,8000-8002`. Values are validated to `1..65535`, sorted, and deduplicated. With no explicit selection, the scanner uses the small default set `{22, 80, 443}` and never silently enumerates all 65535 ports.

The scheduler is bounded by `max_outstanding`, uses the shared Phase 1 `IOEngine` for epoll events and one-shot timers, and retains deterministic target/port/probe ordering. TCP Connect uses actual nonblocking IPv4 sockets and classifies immediate success or `SO_ERROR==0` as `OPEN`, `ECONNREFUSED` as `CLOSED`, and deadline expiry as `FILTERED`; other local socket failures are `UNKNOWN`. Socket events, timers, and descriptors are removed or closed on every terminal path.

The TCP SYN probe reuses the Phase 2 `packet::TCP` model for deterministic offline construction and validates source/destination addresses and ports, SYN/ACK acknowledgment correlation, and RST responses. This build intentionally reports the raw-packet network capability as unavailable; synthetic responses can still exercise the probe and scheduler through an injected transport. It does not claim a real SYN scan.

The minimal CLI is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80,443 --method connect \
  --timeout-ms 500 --max-outstanding 16
```

`--method syn` is accepted as a capability-gated mode and exits without network activity when the raw-packet capability is unavailable. UDP scanning, alternate TCP flag scans, evasion, decoys, spoofing, fragmentation tricks, OS fingerprinting, scripting, dashboards, and bypass mechanisms remain outside scope. Phase 5 service detection is opt-in and limited to bounded TCP banner/probe matching on OPEN results.

## Phase 5 Service Detection

Phase 5 is an opt-in service-detection layer that consumes only `PortResult` values whose state is `OPEN` and whose protocol is TCP. It does not rescan ports, infer service identity from port numbers alone, perform UDP probes, or run operating-system fingerprinting. The CLI performs service probes only after normal IPv4 target validation.

The detector uses the shared Phase 1 `IOEngine` for nonblocking connect, writable, readable, hangup, and timeout events. Its `ServiceScheduler` bounds active probes with `max_outstanding`, bounds each response with `max_response_bytes`, limits attempts per port with `max_probes`, and retains deterministic target/port/probe ordering. Partial TCP responses are accumulated until a matcher succeeds, the peer closes, the response limit is reached, or the shared deadline expires.

Probe definitions are project-owned and stored in `data/service-probes.db` using a compact line-oriented format. Each definition names a TCP payload and one or more prefix, substring, or regular-expression rules. Regex rules may expose numbered captures as `$1`, `$2`, and so on for product and version fields. The built-in dataset is intentionally small and covers HTTP, SSH, FTP, SMTP, a TLS greeting, and a generic banner fallback; it is not an imported Nmap database.

A `ServiceResult` retains the target, TCP port, inherited port state, detection state, service, product, version, extra text, confidence, method, probe name, optional RTT, error classification, and completion timestamp. Matching is deterministic: the highest confidence wins, followed by rule specificity and declaration order. No-match, timeout, connection-closed, oversized-response, malformed, invalid-target and transport-error outcomes remain explicit rather than being converted into guessed service identities.

The CLI extension is:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --method connect \
  --timeout-ms 500 --max-outstanding 16 --service-detect \
  --max-response-bytes 8192 --max-probes 2
```

An explicit project-owned database may be selected with `--service-db data/service-probes.db`. Service detection is performed only after the port scan completes, and only OPEN TCP results enter the service scheduler. The current implementation intentionally does not claim protocol-complete identification, TLS negotiation, credential handling, service exploitation, UDP detection, live OS fingerprinting, or Internet-wide scanning. Phase 5 is complete for this bounded banner/probe scope.

## Phase 6 OS Fingerprinting Architecture

Phase 6 separates **evidence collection**, **runtime data**, **deterministic matching**, and **orchestration**. `OSDetector` consumes an existing `core::Target` plus Phase 4 `PortResult` values and optional Phase 5 service results only to choose usable TCP context; it never derives an operating-system identity from a port number or service label. The scheduler prefers a known OPEN TCP port and otherwise uses the configured explicit probe port for injected/offline work.

The execution path is:

```text
Phase 4 PortResult / optional Phase 5 context
                    ↓
              OSDetector
                    ↓
              OSScheduler
                    ↓
  bounded TCP SYN variants, closed variants, ICMP echo
                    ↓
          OSProbeTransport seam
             ↙                 ↘
 RecordingOSProbeTransport   future capability-gated transport
             ↓
 Phase 1 IOEngine timers and bounded pending map
                    ↓
 packet correlation and OS evidence extraction
                    ↓
 project-owned os-fingerprints.db
                    ↓
 weighted available-evidence OSMatcher
                    ↓
 ranked OSDetectionResult
```

The runtime data file `data/os-fingerprints.db` is intentionally a small Skan-owned laboratory dataset, not a copied broad fingerprint corpus. It supports comments, blank lines, typed numeric and boolean fields, TCP option ordering, response behavior, duplicate detection, missing metadata rejection, and deterministic declaration ordering. Both the CLI and library loader use this project-owned runtime file; no broad external fingerprint corpus is embedded in C++.

Matching uses only fields in `Observed` state. Absent, timed-out, unsupported, and unavailable fields contribute no penalty; observed mismatches reduce confidence. The current weights emphasize TCP option ordering, window, and transport values while retaining TTL, DF, MSS, window scale, SACK, timestamps, flags, behavior, and ICMP evidence. Results are categorized as `NO_MATCH` below `0.30`, `LOW` from `0.30` to below `0.60`, `POSSIBLE` from `0.60` to below `0.85`, and `STRONG` at or above `0.85`. Top-N output is sorted by descending confidence and then fingerprint name.

Probe and scheduler states remain explicit: `Generated`, `Sent`, `ResponseReceived`, `Timeout`, `Unsupported`, and `Malformed`. TCP SYN variants, ECN flags, closed-port variants, ICMP Echo, and an optional offline UDP-port-unreachable representation are available to the model. The recording transport intentionally does not claim UDP or any other live packet capability. `live_os_fingerprinting_available()` is false, so the CLI reports `UNAVAILABLE`, empty matches, and confidence `0` rather than fabricating an identity. Unit and integration tests inject serialized packet responses and never require root privileges, external targets, or public traffic.

The minimal CLI form is:

```sh
./bin/skan os-detect 192.0.2.10 --os-db data/os-fingerprints.db \\
  --timeout-ms 500 --max-outstanding 8 --json
```

In this build that command validates options and database loading, then honestly reports that the live transport is unavailable and sends no probes. The library transport seam is the supported deterministic test path.

## Phase 7 Adaptive Timing + Scan Engine

Phase 7 adds Skan’s own protocol-agnostic, event-driven adaptive timing layer. The validated implementation is complete for the offline and opt-in integration scope described here. It is implemented in `scanengine` and controls scheduling policy rather than TCP, ICMP, UDP, service, or OS packet formats. `TimingProfile` provides named Skan profiles `T0` through `T5`, with `T3` as the stable default. Each profile defines minimum, maximum, and initial parallelism, timeout bounds, RTT multiplier, timeout backoff threshold, recovery threshold, EWMA loss alpha, and bounded retries.

`RttEstimator` accepts only valid correlated response samples. Its first sample initializes `SRTT = RTT` and `RTTVAR = RTT / 2`; later samples use configurable alpha and beta EWMA updates, and `RTO = SRTT + multiplier × RTTVAR`. RTO values are clamped to the profile’s configured timeout bounds. Timeouts, duplicates, late responses, and malformed responses affect lifecycle or congestion accounting but do not create RTT samples.

`CongestionController` tracks bounded current parallelism, response and timeout counts, consecutive outcomes, backoff count, and an EWMA drop estimate. Repeated timeouts reduce parallelism by the configured backoff factor after the configured threshold. Repeated successes increase it by one after the recovery threshold. All changes remain within the configured minimum and maximum; a single timeout does not necessarily halve concurrency.

`ScanGroup` owns an independent generic queue of `ScanWorkItem` values. Work items contain an ID, target string, protocol metadata, timestamps, deadline, retry count, and one of `QUEUED`, `SUBMITTED`, `COMPLETED`, `TIMED_OUT`, `CANCELLED`, or `FAILED`. `AdaptiveScheduler` borrows an existing Phase 1 `IOEngine`, uses one-shot shared timers, maintains a bounded pending map, and accepts an injected protocol-agnostic `ScanTransport`. It handles completion, timeout, retry, cancellation, shutdown, duplicate, late, malformed, and transport-failure events without threads, sleeps, busy loops, or a second reactor.

`TimingController` is the integration seam used by Phase 4 TCP port scanning, Phase 5 service detection, and Phase 6 OS detection when their new `adaptive_timing` configuration flag is enabled. The original static timeout, concurrency, retry, and transport defaults remain unchanged when the flag is false. TCP Connect transport remains nonblocking and unchanged at the transport layer; TCP SYN remains capability-limited/injected; service matching and OS evidence matching remain protocol-specific. The adaptive layer supplies concurrency, timeout calculation, RTT feedback, bounded retries, and metrics without inferring protocol results.

The scan CLI exposes the controls on `scan` without expanding target scope:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80,443 \\
  --method connect --timing T3 --max-outstanding 64 \\
  --min-parallelism 2 --max-parallelism 32 --retries 1
```

Invalid profile, parallelism, timeout, or retry values are rejected. `--retries 0` is valid and remains the conservative default. There is still no implicit `1–65535` port scan. The OS detection command retains its capability-honest unavailable behavior and does not require or imply live raw-packet support.

`ScanMetrics` records queued work, submitted attempts, completed/timed-out/failed/cancelled work, duplicate/late/malformed responses, current and maximum observed parallelism, current/minimum/maximum/average RTT, timeout and retry counts, EWMA drop rate, and elapsed time. Deterministic tests cover the RTT equations and bounds, congestion backoff/recovery, queue and state transitions, retries, cancellation, shared IOEngine timers, multi-group independence, Phase 4 scheduler integration, and a 1000-item offline stress run. No network traffic is generated by the Phase 7 tests.

## Phase 8 Output + Result Serialization

Phase 8 adds a pure presentation layer. It consumes a canonical typed `output::ScanReport` assembled from existing Phase 3–7 result types and performs no scanning, probing, packet construction, detection, scheduling, timing, or network I/O. The `HostResult` model retains discovery state, optional hostname/RTT, `PortResult` values, `ServiceResult` values, ranked `OSMatchResult` values, and warnings/errors. Top-level metadata retains scanner identity, optional timestamps/duration, target specification, timing profile/metrics, and report warnings/errors.

`calculate_summary()` derives host, port, service, and OS counts from the contained result vectors rather than trusting duplicated counters. Optional values remain absent; empty strings, zero, false, unknown state, and no OS matches are distinct representations. Invalid confidence, duration, RTT, empty required identifiers, and non-finite values are rejected with structured `OutputStatus::InvalidReport`.

All writers implement the same `OutputWriter` interface and are independently usable. `OutputManager` only selects a writer; format-specific serialization remains in its own class:

| Format | Behavior |
| --- | --- |
| Normal | Stable terminal-oriented report with hosts, ports, services, OS matches, derived summary, warnings, and errors. Unavailable optional fields are omitted. |
| JSON | UTF-8-preserving standards-compliant JSON with stable key/array order, correct control/quote/backslash escaping, and absent optional fields omitted. |
| XML | Deterministic UTF-8 XML with escaped attributes/text, stable ordering, and omitted optional elements. |
| Grepable | One logical record per line using fixed `Scan:`, `Host:`, `Port:`, `Service:`, `OS:`, `Warning:`, `Error:`, and `Summary:` records with fixed field ordering. Quoted values use backslash escaping for quotes, backslashes, tabs, carriage returns, and newlines. |

Hosts are sorted by canonical address, ports by numeric port and protocol, services by associated port, and OS matches by descending confidence followed by ascending name. Repeated serialization of one report is byte-identical. Untrusted banner/product/version data is escaped or control-sanitized in every format; machine formats never emit terminal color codes.

The scan CLI accepts `--output normal|json|xml|grepable` and defaults to `normal`. `-o <file>` and `--output-file <file>` write the selected serialization through an RAII `std::ofstream`, explicitly truncating/replacing the selected path. File-open and serialization failures are reported on stderr and do not create a partial success message on stdout. Standard output contains only the selected serialization; operational logs and diagnostics go to stderr. Existing `--version`, target validation, port selection, service detection, OS capability behavior, and Phase 7 timing flags remain additive and unchanged.

Examples:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output normal
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output xml
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output grepable
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json -o scan.json
```

The grepable schema is intentionally small and script-friendly. `Port` records contain `target`, `number`, `protocol`, `state`, `probe`, `reason`, and optional `rtt_ms`; `Service` records contain target/port/protocol/state/port-state, optional identity fields, confidence, method, and error; `OS` records contain address, name, confidence, and class. `Summary` contains derived host, port, service, and OS counts. No writer reconstructs information from another writer.

## Phase 9 Network Transport + Packet Capture

Phase 9 adds infrastructure for connecting future packet-producing and packet-consuming components to Linux interfaces. It does not add a new scan mode. The `net` module is divided into interface discovery, byte transport, bounded packet capture, packet observation, small protocol/port filtering, and a reusable correlation-table boundary.

`NetworkInterface` contains the kernel interface name, index, IPv4 addresses with prefix lengths, operational state, and separate capture/injection capability flags. Linux enumeration uses standard interface APIs, returns structured `InterfaceStatus` errors through `enumerate_interfaces_result()`, and returns interfaces in deterministic name order. `find_interface()` performs exact-name lookup. Skan never silently selects an interface for privileged packet injection; callers must explicitly provide `TransportConfig::interface_name` or `CaptureConfig::interface_name`.

`Transport` moves only already-serialized bytes. `RecordingTransport` records exact frames without network access or privileges, and `NullTransport` accepts configuration while intentionally transmitting nothing. `LinuxTransport` uses an explicitly selected Linux `AF_PACKET` socket, has an explicit open/close lifecycle, preserves system errors, uses nonblocking send behavior when configured, and owns its descriptor through a move-only RAII wrapper. It never chooses ports, creates packets, modifies source identity, fragments frames, or implements evasion.

`PacketCapture` is independent from scan strategy. `LinuxCapture` uses an explicitly selected, nonblocking `AF_PACKET` socket and bounded `recvmsg(MSG_TRUNC)` reception, so oversized frames are reported instead of being silently accepted. `RecordingCapture` supplies deterministic synthetic frames to tests. `PacketReceiver` copies only bounded frames and passes them through the existing Phase 2 Ethernet, IPv4, TCP, UDP, and ICMP parsers, preserving deterministic timestamps and distinguishing truncation, malformed data, unsupported protocols, and valid observations. Its descriptor can be attached to the existing Phase 1 `IOEngine`; no second reactor, polling thread, or blocking receive loop is introduced.

`PacketFilter` supports only the small protocol and source/destination-port predicates required before future correlation. `CorrelationTable` provides deterministic insertion, duplicate detection, lookup, removal, late-packet rejection, and deadline cleanup. It is a reusable boundary rather than a scanner or packet strategy.

The infrastructure-only CLI command is:

```sh
./bin/skan interfaces
./bin/skan interfaces --json
./bin/skan interfaces --interface lo --json
```

Normal output lists interface name, index, IPv4/prefix values, state, capture capability, and injection capability. JSON output uses stable interface and address ordering and contains only interface data. A missing raw-socket privilege is reported as unavailable capability in the listing or as a structured `PermissionDenied` result when opening a Linux transport or capture backend; no fake successful transmission or fabricated packet response is produced.

> Skan's network transport is capability-honest. When packet capture or injection is unavailable, Skan reports the unavailable capability and does not fabricate successful network operations or packet responses.

Linux AF_PACKET support is Linux-specific and normally requires the privileges permitted by the host's network policy. The controlled integration test uses only the local loopback interface and reports `SKIPPED` when the environment lacks the required capability. Phase 9 does not implement stealth or decoy scanning, source spoofing, evasion, IDS/IPS bypass, fragmentation attacks, credential handling, exploitation, persistence, Internet-wide scanning, or public-target traffic.

## Phase 2 Packet Layer

The packet layer remains below discovery and is responsible for protocol representation, validation, deterministic serialization, checksums, and lightweight parsing. Discovery does not duplicate ICMP or TCP packet construction. Packet elements continue to serialize into caller-provided `std::span<std::uint8_t>` buffers and provide owned-vector convenience forms.

| Element | Current support |
| --- | --- |
| Ethernet II | Destination/source MAC, EtherType, fixed 14-byte header, validation, parsing |
| IPv4 | Version 4, fixed 20-byte header, fields, addresses, checksum, parsing |
| TCP | Ports, sequence/acknowledgment numbers, flags, supported options, payload, IPv4 pseudo-header checksum, parsing |
| UDP | Ports, derived length, payload, IPv4 pseudo-header checksum, parsing |
| ICMPv4 | Echo Request and Echo Reply, identifier, sequence, payload, checksum, parsing |
| Packet | Ordered Ethernet → IPv4 → TCP/UDP/ICMP composition and offline serialization |

## Requirements

A Linux environment with GNU Make, GCC, and G++ is required. Normal builds use C++20/C11, `-O2`, and the repository's strict warning flags. Debug builds use `-g -O0`. The Phase 1 backend requires Linux epoll.

## Build

Build the executable with:

```sh
make
```

The executable is written to `bin/skan`. Object files, dependency files, and test binaries are written below `build/`; generated files are not placed in `src/` or `include/`.

For a debug build, use:

```sh
make debug
```

## Tests

Compile and execute all Phase 0 through Phase 9 tests with:

```sh
make test
```

The suite includes deterministic unit tests for discovery and port-selection parsing; TCP Connect and TCP SYN probe classification; Phase 2 TCP packet reuse; service database parsing; prefix, substring, and regex matching; bounded service scheduling; partial responses; malformed, oversized, duplicate, and late responses; invalid-target handling; timeouts; retries; multiple targets; and stress-sized synthetic scans. Phase 6 adds owned OS database parser tests, typed observation and weighted matcher tests, packet-backed probe correlation tests, bounded multi-host scheduler tests, and injected detector integration tests. Controlled local integration tests exercise real loopback TCP Connect and real SSH/HTTP banner detection without using public targets. Phase 9 adds deterministic interface, offline transport/capture, packet receiver, filtering, correlation, Linux lifecycle, and controlled loopback capability tests. Existing Phase 0–8 tests remain active.

Sanitizer validation can be run with:

```sh
make clean
make test CXXFLAGS='-std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' CFLAGS='-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined'
```

## CLI usage

The CLI remains intentionally small. Phase 0 commands are preserved:

```sh
./bin/skan --version
./bin/skan --help
```

Phase 3 adds a loopback-scoped discovery exercise:

```sh
./bin/skan discover 127.0.0.1 --icmp --timeout-ms 10
./bin/skan discover 127.0.0.1 --tcp --tcp-port 80 --timeout-ms 10
```

The discovery CLI uses the offline recording transport. It reports `UNKNOWN` when no synthetic response is injected; it does not open a raw socket or connect to the target. ARP is available to the packet/probe unit tests and future lab transports, but the CLI does not claim an Ethernet interface.

Phase 4 adds the TCP Connect exercise:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 1,22,80 --method connect --timeout-ms 100
```

Phase 5 adds opt-in service detection after OPEN TCP results:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --method connect \
  --service-detect --service-db data/service-probes.db
```

Phase 6 adds a capability-honest OS detection command:

```sh
./bin/skan os-detect 192.0.2.10 --os-db data/os-fingerprints.db \
  --timeout-ms 500 --max-outstanding 8
./bin/skan os-detect 192.0.2.10 --json
```

The default live OS transport is unavailable in this build, so both forms report `UNAVAILABLE` with empty matches and zero confidence; no OS identity is inferred without injected response evidence.

Phase 8 adds deterministic output selection for `scan`, and Phase 9 adds infrastructure interface inspection:

```sh
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output normal
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output xml
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output grepable
./bin/skan scan 127.0.0.1 --tcp-ports 22,80 --output json --output-file scan.json
```

The default is `normal`. `-o` and `--output-file` explicitly replace the selected file; serialized results remain separate from stderr diagnostics. Invalid output formats fail before scanning.

The `interfaces` command does not scan or transmit; it reports the interfaces visible to the current Linux environment. Unknown or incomplete arguments print a clear error and return a non-zero status. There is no hidden target-selection path, implicit public-target default, UDP option, alternate TCP flag option, or full-port-range default.

## Network and safety boundary

Phase 4 implements IPv4 TCP Connect transport through nonblocking stream sockets, and Phase 5 adds TCP banner/probe service detection on OPEN results. Phase 9 adds explicit-interface Linux `AF_PACKET` byte transport and bounded capture as reusable infrastructure; these classes do not choose scan strategies, implement SYN scanning, spoofing, ARP attack behavior, host-range expansion, public-target defaults, UDP scanning, alternate TCP flag scanning, evasion, live operating-system fingerprinting, Lua scripting, or dashboard functionality. Phase 6 provides packet-model-backed synthetic/injected OS evidence collection and deterministic matching only; it does not claim a live OS fingerprint. Phase 9's transport transmits only bytes supplied by higher layers and reports unavailable capabilities rather than fabricating success.

The Phase 3 integration remains offline. Phase 4 and Phase 5 integration use only `127.0.0.1` and deliberately created local listening sockets; Phase 5 additionally verifies controlled SSH and HTTP banner responses. Phase 9's controlled Linux integration uses only the local `lo` interface and does not send traffic; capability-dependent capture tests skip cleanly when raw-socket privileges are unavailable. No public Internet targets were scanned.

## License

The repository currently contains a `License: TBD` placeholder. No open-source license has been selected.
