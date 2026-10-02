# Service V3 audit and first vertical slice

Audit baseline: `af4b3d1e2d11bfbf3291c0f3e876d064e8e6adbf` (main,
2026-09-23). This is a scoped engineering audit, not a superiority claim.

## Verified baseline

- Runtime declarations and canonical manifest agree: **49 active probes,
  150 service matchers, 51 OS records (27 IPv4 + 24 IPv6), 21 UDP probes**.
  The migration command's `service_records=199` combines probes and matchers;
  it does not mean 199 matchers.
- Prioritized probes, explicit fallbacks, hard/soft ranking, bounded responses,
  target attribution, stream accumulation, delayed retries and negative port
  evidence reconciliation already exist. Preserve these mechanisms.
- `make test` passed before changes: registered C++ executables, 213 corpus
  tests and 46 comparison tests. The runtime semantic round trip passed.
- Reviewed README, compatibility/intelligence/service documentation, benchmark
  report, build targets, corpus/data, engine/result interfaces, relevant tests
  and CI jobs. Recent mainline fixes address corpus integration, fragmented
  service responses and transient scanning failures.
- Open PRs #14, #18, #19, #20, #21 and #22 are old stacked work. Recent merged
  PRs #77–80 repaired integration/build/corpus state. Their open/closed status
  alone must not be used to infer which implementation is present on main.

## Prioritized verified gaps

| Priority | Evidence | Next action |
| --- | --- | --- |
| P0 | MQTT rules accepted a two-byte prefix and reserved flag bits; a fixture explicitly expected malformed `20 02 0a 00` to match at 0.99 | Request-scoped protocol framing and negative regression tests (this slice) |
| P0 | Many HTTP/API and binary fingerprints still rely on regex/prefix rules; two Elasticsearch rules cover field order, not JSON structure | Incremental protocol validators; structured HTTP/JSON scope and collisions next |
| P0 | Rule confidence is authored, not an empirically calibrated probability; corpus fixtures are synthetic | Labeled captures, independent verification and per-protocol calibration |
| P0 | `OSMatcher` uses the first TCP observation for multiple fields, rather than matching every field against its intended probe | Probe-scoped OS evidence before expanding OS labels |
| P1 | TLS inspection is a raw handshake parser, not a completed TLS 1.3 session | Bounded TLS session transport; explicit unavailable encrypted metadata |
| P1 | `data/*.db` is runtime authority; canonical records are a round-trip-checked mirror | Deliberate canonical-authority migration, signed/atomic updates; no second independent truth |
| P1 | Comparison schema v1 intentionally blocks superiority claims; offline ops/s are not accurate network results/s | Equivalent controlled workloads and truth-labeled benchmark v2 |
| P1 | CI fuzz job builds a fuzz binary but does not execute a fuzz campaign | Explicit bounded fuzz execution with retained reproducers |

## First slice: MQTT CONNECT to CONNACK evidence

Use the existing matcher and scheduler. Before publishing an MQTT match,
validate the actual request bytes and the complete first response frame.
No new network operation, credentials, subscription or publish is introduced.
Port number and probe name are not sufficient evidence.

The validator intentionally supports only the installed 18-byte MQTT 3.1.1
CONNECT: clean session, client identifier `skan`, no credentials or will.
Other request profiles and MQTT 5 are **unsupported by this validator** and
cannot produce a validated MQTT match. They remain UNKNOWN under the existing
no-match/fallback contract. This is not a general-purpose MQTT client.

Accepted framing is `20 02 00 rc`, where `rc` is 0..5. Reject wrong packet
type/flags, length, reserved acknowledgement bits and contradictory session
state. A partial first frame does not become cached evidence. Later coalesced
bytes are outside this first-frame observation and neither provide nor revoke
that evidence. Input remains capped at 8,192 bytes; validation examines four
response bytes and one fixed-size request, with no allocation or recursion.

The existing scheduler supplies request/target correlation, accumulation,
deadlines, response limits and fallback. A CONNACK has no transaction ID:
correlation is to the outstanding connected TCP exchange, not an invented ID.
Malformed or truncated responses yield no MQTT match, not a broker identity.

### Identity and evidence contract

- `service=mqtt`; `product` and `version` remain absent. CONNACK does not expose
  broker implementation or release identity.
- Optional `mqtt` evidence is attached to the selected match and copied to the
  canonical service result. JSON/XML/grepable writers preserve it.
- Validator ID: `mqtt-3.1.1-connack-v1`; requested protocol: `3.1.1`;
  return code: observed byte; session present: false; frame length: 4.
- `accepted_protocol=3.1.1` is emitted **only** for return code zero. A refusal
  proves neither successful negotiation nor a product version.
- Existing corpus confidence is retained as a heuristic rule score, **not**
  a measured 99% probability. No calibration or comparative accuracy is claimed.
- Generic/custom MQTT rules cannot bypass validation. Non-MQTT rules retain
  their existing behavior. Runtime DB and canonical artifacts are unchanged.

### Verification scope

Regression tests exhaust all 65,536 combinations of acknowledgement flags and
return code, every fixed-header/length byte value, truncation boundaries,
unrelated request/transport, response limits and coalescing. Scheduler tests
exercise every split point, both address families and terminal truncation.
Machine-output tests distinguish acceptance/refusal and reject invalid typed
evidence. The fuzz harness now provides a valid fixed MQTT database/request so
mutated binary responses actually reach the validator.

These are project-authored synthetic protocol fixtures, not captured broker
measurements. Positive, collision and malformed fixtures derive independently
from [OASIS MQTT 3.1.1 sections 3.1–3.2](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).
No Nmap fingerprint content is used. This does not complete Service V3, prove
real-world false-positive rates, or satisfy the full product roadmap.
