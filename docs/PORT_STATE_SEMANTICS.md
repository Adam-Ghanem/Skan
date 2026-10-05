# Port-State Semantics — normative CORE-02

All states describe the selected interaction at observation time. Neither a port
number nor a service guess supplies port-state evidence. “Definitive” below means
the observation proves its stated property; it does not establish permanent
availability. FILTERED retains endpoint ambiguity: an administrative rejection
proves filtering, while a timeout only represents the scan policy's unresolved
path. Silence cannot prove a firewall exists.

| State | Meaning / evidence | Allowed methods | Certainty |
| --- | --- | --- | --- |
| OPEN | Endpoint accepts the interaction: successful connect, correlated SYN/ACK, valid correlated UDP response | Connect, SYN, UDP | definitive positive |
| CLOSED | Definitive endpoint rejection: connection refused, correlated SYN reset, UDP port-unreachable quote | Connect, SYN, UDP | definitive negative |
| FILTERED | Filtering evidence or completed TCP silence policy prevents endpoint determination | Connect, SYN, ACK, UDP (explicit filtering only) | endpoint ambiguous |
| UNFILTERED | Correlated ACK reset proves the ACK reaches the endpoint path; does not prove a listener | ACK only | definitive path property, service unknown |
| OPEN_OR_FILTERED | UDP silence cannot distinguish a listener from filtering/loss | UDP only | ambiguous |
| UNKNOWN | Insufficient or conflicting admitted evidence | all | ambiguous |
| ERROR | Local scanner/runtime failure prevents valid classification | all | no endpoint inference |
| UNREACHABLE | Valid path/network evidence reports failed reachability | all | definitive path failure, service unknown |

## State and reason matrix

| Method | Validated evidence | State | Typed reason |
| --- | --- | --- | --- |
| Connect | kernel connect success | OPEN | ImmediateSuccess |
| Connect | ECONNREFUSED | CLOSED | ConnectionRefused |
| Connect | ETIMEDOUT or expired completed policy | FILTERED | Timeout |
| Connect | ENETUNREACH/EHOSTUNREACH/ENETDOWN/EHOSTDOWN | UNREACHABLE | NetworkUnreachable |
| Connect | EADDRNOTAVAIL | ERROR | LocalAddressUnavailable |
| Connect | other local socket failure | ERROR | SocketError |
| SYN | exclusive correlated SYN+ACK, expected acknowledgement | OPEN | SynAck |
| SYN | correlated RST without SYN/FIN | CLOSED | Rst |
| SYN | completed silence policy | FILTERED | Timeout |
| ACK | bare RST with sequence equal to sent acknowledgement | UNFILTERED | AckRst |
| ACK | completed silence policy | FILTERED | AckTimeout |
| UDP | valid datagram, correct endpoints/ports, bounded framing | OPEN | UdpResponse |
| UDP | quoted port-unreachable | CLOSED | IcmpPortUnreachable |
| UDP | completed silence policy | OPEN_OR_FILTERED | UdpTimeout |
| raw methods | quoted administrative prohibition | FILTERED | IcmpAdministrativelyProhibited |
| raw methods | quoted network/path unreachable | UNREACHABLE | IcmpNetworkUnreachable |
| SYN, ACK | quoted TCP protocol-unreachable | FILTERED | IcmpProtocolUnreachable |
| SYN, ACK | quoted TCP port-unreachable (not TCP reset) | FILTERED | IcmpPortUnreachable |
| all | conflicting admitted canonical states | UNKNOWN | ConflictingEvidence |
| all | local transport/runtime failure | ERROR | SocketError/InternalError/CapabilityUnavailable |

Wire spellings of typed reasons are defined by `scan_reason_name` and retain
existing uppercase names. Diagnostic reasons MalformedResponse,
UnrelatedResponse, DuplicateResponse and LateResponse do not prove an endpoint
state. InvalidTarget/InvalidPort/UnsupportedMethod/UnsupportedProtocol represent
local validation errors. They cannot justify OPEN/CLOSED/FILTERED.

An uninitialized `PortResult` remains UNKNOWN/InternalError until assessment;
this is not a published local failure. Published failures require ERROR. Report
validation rejects forbidden method/state/reason/protocol combinations.

## ICMP mapping

All rows require validated outer framing and a sufficient correctly correlated
quote. IPv4 destination-unreachable type 3: codes 0/1/5/6/7 imply path failure;
9/10/13 imply administrative prohibition. Protocol/port rejection (2/3) cannot
prove a TCP listener is closed, so preserves filtering/endpoint ambiguity; UDP
code 3 is CLOSED. Unsupported/other codes cause no state transition.
IPv6 destination-unreachable type 1: 0/2/3 imply path failure, 1/5/6 imply
administrative/policy prohibition, 4 proves UDP CLOSED but does not prove a TCP
listener is closed. IPv4 and IPv6 therefore share canonical semantics, with
different wire codes. Time-exceeded and packet-too-big do not prove a listener
state and are ignored by this phase's port classifier.

## State machines and conflicts

Raw SYN/ACK/UDP start without accepted evidence. A valid observation is retained
until the current attempt deadline. Repetition of the same state preserves it.
Different admitted states irreversibly replace it with UNKNOWN and
ConflictingEvidence. At the deadline, a retained result is published; silence
uses bounded retries then the method's silence state. Malformed, unrelated,
stale, wrong-target, wrong-port and insufficient quotes make no transition.
Local failure immediately terminates as ERROR because observation is incomplete.

SYN/ACK then RST and RST then SYN/ACK both yield UNKNOWN if admitted during the
same lifetime. ICMP then TCP follows the same rule. Duplicate SYN/ACK and RST
are idempotent. Packets for retired attempts are ignored, including late
duplicates; a result never changes after publication. Conflicting SYN/RST flags
in one packet are invalid and cause no transition.

Connect starts per socket attempt. Success publishes OPEN; refused and timeout
follow bounded negative confirmation. Mixed negative categories remain UNKNOWN,
even when another negative category repeats. A successful later connect proves
current acceptance and publishes OPEN. Local failure cannot be FILTERED.

## Invariants / insufficient evidence

OPEN requires positive evidence; timeout is invalid for OPEN. CLOSED requires
endpoint refusal/reset/UDP port-unreachable; timeout or admin-prohibited is
invalid. ACK never emits OPEN, CLOSED or OPEN_OR_FILTERED. TCP Connect never
emits OPEN_OR_FILTERED. UDP silence never emits OPEN. SYN silence never emits
CLOSED. Local ERROR never enters filtering counters. Generic timeout never
emits UNREACHABLE. Any observed conflict remains ambiguous.

## CLOSED_OR_FILTERED decision

Intentionally absent. No currently supported scan family proves precisely
closed-or-filtered while excluding open. Connect/SYN can prove endpoint refusal;
ACK cannot distinguish open from closed; UDP silence admits open. Insufficient
or conflicting evidence is UNKNOWN. Adding an enum solely for parity would
misrepresent the evidence.
