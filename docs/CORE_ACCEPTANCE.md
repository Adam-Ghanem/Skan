# CORE-02 Acceptance

The phase is accepted only at the final reviewed commit when every gate below
has recorded evidence. Pending or missing evidence is not a pass.

- Canonical states, certainty, per-method transitions, reasons, ICMPv4/v6,
  conflicts and CLOSED_OR_FILTERED decision: `PORT_STATE_SEMANTICS.md`.
- Architecture/evidence/output invariants: `CORE_SCANNER_SPEC.md`.
- Deterministic table matrix: real probes/schedulers, state and reason assertions.
- Negative cases: malformed/unrelated/stale/wrong tuple/truncated quotes,
  forbidden ACK states, UDP/SYN silence, local/path failures and conflicts.
- CORE-01 truth lab: IPv4/v6 SYN open/closed/drop/admin with exact reasons;
  IPv4 ACK reset/drop/admin with exact reasons; IPv4 Connect refusal/success;
  IPv4 UDP open/closed with exact reasons. IPv6 UDP truth remains represented
  by the independent manifest/spec, but live non-loopback raw IPv6 UDP transport
  enablement is a pre-existing CORE-11/CORE-13 capability gap, not a CORE-02
  semantic rewrite. Preserve independent truth, snapshots and packet captures.
  No public targets.
- All serializers preserve full states/reasons; eight disjoint counters sum to
  ports_scanned; terminal widths and --open filtering remain correct.
- Full registered relevant tests, ASan and UBSan pass. Record commands and
  unavailable gates; never equate unavailable with passed.
- Full diff and independent review show only CORE-02 changes.
- Phase branch is `core/v3-port-state-spec`, based on latest allowed main.
- Final exact-head CI is entirely green before merge; post-merge main CI is
  green before CORE-03. No CI polling/waiting between implementation steps.

## Execution evidence

Implementation in progress. The base `bf42e46` has twelve completed successful
Skan CI checks, inspected once before implementation. This is baseline evidence,
not CORE-02 completion evidence. Final results are recorded at delivery.
