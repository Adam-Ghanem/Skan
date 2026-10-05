# Core Scanner Contract — CORE-02

This document and `PORT_STATE_SEMANTICS.md` are normative. `CORE_ACCEPTANCE.md`
defines the evidence required to accept an implementation. Keywords MUST and
MUST NOT are requirements. Baseline: `bf42e4667805553529106e261dda331cd3d7be06`.

## Evidence boundary

The pipeline is packet evidence → validated observation → canonical PortResult.
Parsers MUST validate framing, lengths and checksums before transport correlation.
Transports MUST correlate both endpoint addresses, transport ports and the
available probe identity before emitting an observation. An ICMP error identifies
the probed endpoint through its quoted packet; its outer source may be a router.
An incomplete quote, unrelated tuple, invalid flags or retired identity MUST NOT
classify a port. Scope/interface/generation identity expansion belongs to CORE-03.

Each raw attempt has a bounded observation lifetime: submission until its existing
configured deadline. Valid responses are accumulated until this deadline; silence
alone follows the existing retry policy. Duplicate evidence is idempotent.
Two admitted observations with different canonical states produce
UNKNOWN/CONFLICTING_EVIDENCE regardless of arrival order. Once conflicting,
additional evidence cannot restore a definitive classification. An observation
dated before submission is stale and MUST be ignored. Retired attempts cannot
change a published result. No added settling delay or retry algorithm is required.

TCP Connect uses kernel socket completion rather than raw packet observations.
Its existing bounded negative-confirmation policy is preserved: refused,
timeout and local socket failures may be confirmed within the retry budget;
contradictory negative categories produce UNKNOWN/CONFLICTING_EVIDENCE.
A later successful connect proves acceptance at that attempt and yields OPEN.
This is temporal endpoint evidence, not an assertion that a previous refusal
never occurred. A majority of negative observations MUST NOT hide a conflict.

## Local and path failures

Local socket/resource/capture/timer/submission failures produce ERROR and their
typed reason. They MUST NOT be treated as filtering or network reachability.
Path-unreachable ICMP or kernel route errors produce UNREACHABLE. A deadline
alone never proves UNREACHABLE. Malformed remote input is ignored; it is not a
local ERROR. Unsupported modes and invalid input fail explicitly.

## Output contract

PortResult.state and PortResult.reason are the only sources of classification.
Every renderer MUST preserve the complete canonical state name; reasons retain
their stable typed spellings. JSON/XML/grepable/normal may differ in formatting,
never in state. Summary buckets are disjoint and sum to ports_scanned. ERROR,
UNREACHABLE, UNKNOWN and UNFILTERED MUST NOT count as FILTERED.
`--open` includes OPEN and OPEN_OR_FILTERED rows; totals still describe all
scanned ports. Existing service visibility policy is unchanged.

## Audit of the starting implementation

The enum already contains eight states. TCP Connect maps local failures to
UNKNOWN, confirms some negatives, and can overlook mixed negatives after two
matching observations. SYN accepts conflicting flag combinations at the probe
boundary. TCP transports collapse administrative ICMP into unreachable. ACK
maps that category to FILTERED without preserving its reason. UDP maps path
errors to FILTERED and malformed responses to ERROR. Raw transports retire on
the first response, preventing admitted contradictory evidence from being
represented. Timestamp checks are absent. Fatal capture errors can become
timeouts. Output names are shared, but human state cells truncate
OPEN_OR_FILTERED and summaries omit five state buckets. These are CORE-02
contract violations; targeted regression fixes are permitted.

## Scope

No new scan family, correlation generation/key redesign, adaptive timing,
scheduler architecture, service/OS detection or vulnerability feature is part
of this phase. Existing bounded pending records may retain observations to
implement the required semantics. No Nmap code or data is incorporated.

Protocol references: [TCP RFC 9293](https://www.rfc-editor.org/rfc/rfc9293),
[ICMP RFC 792](https://www.rfc-editor.org/rfc/rfc792),
[ICMPv6 RFC 4443](https://www.rfc-editor.org/rfc/rfc4443). These describe wire
evidence; Skan's classification and timeout policy is specified here.
