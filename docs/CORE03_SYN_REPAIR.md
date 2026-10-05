# CORE-03 SYN evidence boundary investigation

This is a bounded repair on `core/v3-correlation`, based on `b75afca`.
It is **not** a declaration that CORE-03 or correlation V3 is complete.

## Historical failure remains real

The historical CORE-02 executable returned TIMEOUT for both the independently
listening OPEN port and the CLOSED port, including after neighbor-cache priming.
Increasing its deadline from 500 ms to 3000 ms did not resolve the failure.
The independent capture contains checksum-valid SYN/ACK and RST/ACK replies:

| Probe | Local endpoint | Remote endpoint | Sent sequence | Reply acknowledgment |
| --- | --- | --- | --- | --- |
| OPEN SYN | 192.0.2.5:40001 | 192.0.2.6:18080 | 1119318455 | 1119318456 |
| CLOSED SYN | 192.0.2.5:40002 | 192.0.2.6:18082 | 1124312030 | 1124312031 |

The OPEN reply has only a recognized MSS option; the CLOSED reply has no TCP
options. Replaying these literal frames through the current parser, tuple/ACK
validator and correlation lookup succeeds. A clean build from the current main
base also passes the live OPEN/CLOSED test. Therefore the exact cause of the
historical binary's failure is **not established**, and the repair below must
not be described as proving that historical root cause. The old dirty worktree
and its evidence were preserved rather than integrated wholesale.

## Proven related rejection and minimal repair

The transport parsed and validated a reply, admitted its tuple/ACK, then tried
to serialize the parsed TCP object again for the scheduler. TCP parsing skips
unknown options and stops at End-of-Option-List, while retaining the original
wire data offset. Re-serialization can consequently reject an otherwise valid
header because the retained modeled options are shorter than that data offset.
That silent loss can manufacture a timeout after successful correlation.

The regression first failed at `bytes.has_value()` with a valid unknown-option
reply. The transport now copies the bounded TCP segment from the **already
validated raw frame**, after the unchanged admission checks. IPv4 header size,
IPv6 extension consumption, VLAN offset, declared packet length and capture
bounds determine the span. It does not reconstruct or repair untrusted bytes.
No tuple check, checksum validation, sequence/ACK rule or correlation lookup
was removed or bypassed. No generation identifier was removed.

Tests include the literal historical OPEN/CLOSED frames; unknown options, EOL
padding and MSS over both IP families; VLAN and IPv6 destination extensions;
wrong tuple/ACK, malformed checksums, empty/truncated wire buffers and retired
lookup entries. TCP probe assessment asserts OPEN/SYN_ACK and CLOSED/RST with
the extracted bytes; wrong response IDs remain rejected. Ethernet padding and
combined VLAN/IPv6-extension/padding captures preserve exactly the TCP segment.
Existing ACK and ICMP-quote rejection tests remain in place.

## Opt-in end-to-end diagnostics

`--debug` records submission ID, family, local/remote addresses and ports,
selected capture interface, scope, sequence/ACK, send completion, parser status,
lookup key/status, validation rejection field, retirement and scheduler evidence.
Rejection labels distinguish parser, AF, protocol, source/destination address,
source/destination port, TCP sequence, TCP acknowledgment, flags/probe,
wire bounds and lifecycle. Formatting failures cannot change packet admission.

In the observed current live trace:

1. Probe 1 submits the OPEN tuple and sequence 1119318455; 54 wire bytes are sent.
2. The 58-byte SYN/ACK parses as valid; lookup finds probe 1 with ACK minus one
   equal to 1119318455; the validator admits it; scheduler records OPEN/SYN_ACK.
3. Probe 2 submits the CLOSED tuple and sequence 1124312030; 54 wire bytes are sent.
4. The 54-byte RST/ACK parses as valid; lookup finds probe 2 with ACK minus one
   equal to 1124312030; scheduler records CLOSED/RST.
5. Captured outbound packets fail the destination-address check. Unrelated
   malformed ICMPv6 traffic fails the parser check, not TCP correlation.

Interface isolation currently comes from the bound capture socket. IPv6 scope
is checked when selecting a source/interface; it is not carried on the wire.
The existing correlation key has no explicit scan/probe generation fields;
diagnostics truthfully say `generation=not-implemented`. Expanding the key and
proving late/reused-identity rejection remain CORE-03 work, not capabilities
claimed by this repair.

## Validation scope and limitations

All live traffic stayed inside the authorized CORE-01 namespace/veth lab.
Live smoke validation passed SYN IPv4/IPv6 OPEN, CLOSED, DROP and administrative
reject; ACK IPv4/IPv6 RST, DROP and administrative reject; TCP connect IPv4;
and UDP IPv4 response/port-unreachable. ACK IPv6 is now included in the lab's
strict acceptance assertions. Independent capture and listener/firewall
snapshots accompany local ignored evidence in `validation_runs/`.

Four targeted transport/filter/receiver tests passed, including address and
undefined-behavior sanitizer builds. The lab contract's six tests, version
consistency and line-ending checks passed. Full-suite execution and independent
review results are recorded below after completion; a timeout is not a pass.

Known gaps:

- The exact historical OPEN/CLOSED timeout cause is unresolved on the preserved
  stale executable; current-base success is not proof of its cause.
- Explicit generation and expanded correlation-key protections are not yet
  implemented in the base and are not supplied by this narrow wire-evidence fix.
- Non-loopback UDP IPv6 neighbor resolution is not implemented by the existing
  UDP transport unless an explicit destination MAC is supplied. This run does
  not claim live non-loopback UDP IPv6 coverage; IPv6 UDP parsing/correlation
  regressions are exercised by existing unit tests.
- GitHub CI is asynchronous and is not polled/waited for. No full-phase
  acceptance or merge is claimed without final exact-head green evidence.

## Execution ledger

- First large clean build/full-suite attempts reached their explicit timeout
  while making compiler/linker/corpus progress; incremental retries were used.
- An initial lab invocation used the unsupported `--artifacts` argument and
  failed argument validation; the correct `--evidence-dir` invocation passed.
- Initial scratch pcap replay linking failed on omitted discovery objects;
  corrected linking passed. This scratch tool is not a substitute for tests.
- The unknown-option RED regression failed as expected before the wire fix.
- The repaired live smoke exited 0; local artifact directory:
  `validation_runs/core03-wire-fix` (not committed).
- Targeted ASan/UBSan invocation exited 0; this is four targets, not a claim
  that the entire test suite was run under sanitizers.
- Final repaired live smoke and a separate debug trace exited 0 using the final
  production build; artifacts are in `validation_runs/core03-final` and
  `build/core03-syn-trace.*` (not committed). Independent `tcpdump` inspection
  confirms the OPEN response's checksum and acknowledgment.
- Concurrent local test/build orchestration caused `Text file busy` while a
  linked executable was being replaced. That attempt was not a pass. Shared
  normal-build targets were subsequently verified serially; sanitizer objects
  use a separate build directory.
- Independent read-only whole-diff and follow-up review found no blockers.
  Both suggested test improvements (probe assessment and combined/padded
  captures) were implemented and the targeted test passed again.
