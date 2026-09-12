# Service Detection Correctness v2 Design

## Goal

Make `-sV` prefer protocol evidence over guesses and refuse to publish weak,
ambiguous banner matches as detected services. A service remains valid on any TCP
port: an HTTP response on port 22 is HTTP evidence, not an error merely because
the port is commonly assigned to SSH.

## Findings

The matcher ranks candidates within one probe by match strength, structural
priority, confidence, specificity, and declaration order. The scheduler does not
preserve those semantics across probes: it compares soft matches by confidence
alone and replaces equal-confidence evidence with the later probe. It also
publishes very weak generic soft matches (currently as low as 0.40) as detected
services.

## Design

1. Introduce one deterministic comparison function for `ServiceMatchResult` and
   use it both inside a probe and across probes.
2. Prefer hard evidence, then publishable evidence, then structurally stronger
   match forms, confidence, and specificity. This prevents a structurally exact
   but unusably weak soft match from hiding a strong publishable match. Exact ties
   keep the earlier result so probe ordering remains meaningful and deterministic.
3. Require a minimum confidence of 0.60 before a soft match can become a detected
   service. Weaker matches remain internal hints and the public result is
   `Unknown` with `NoMatch` after probe exhaustion.
4. Preserve immediate completion for hard matches and preserve cross-port
   detection. Port hints choose probe order only; they never override response
   evidence.
5. Keep the threshold and comparator explicit, typed, testable, and independent
   of terminal rendering.
6. Require exact non-empty target attribution on data, close, and error responses;
   mismatched responses cannot advance or finalize another probe.

## Database Growth Policy

The service corpus will grow only through clean-room signatures derived from
public protocol specifications, first-party synthetic fixtures, and explicitly
licensed sources. Every product/version signature must have a deterministic
positive fixture and relevant negative/collision fixtures. Counts are a result,
not the acceptance criterion; untested generated patterns and copied Nmap data
are prohibited.

## Rejected Alternatives

- Binding services to conventional ports: breaks legitimate cross-port services.
- Hiding low-confidence results only in the renderer: structured outputs would
  still leak incorrect classifications.
- Adding thousands of port-name aliases: this is not service fingerprinting.
- Copying third-party scanner databases: incompatible with the clean-room and
  licensing requirements.

## Acceptance Criteria

- A weak generic soft match does not produce `Detected`.
- A strong soft match still produces `Detected` after all probes finish.
- A later equal or inferior soft match cannot replace earlier superior evidence.
- A standards-conforming HTTP response is identified as HTTP even on port 22.
- Existing service matcher, scheduler, local detection, and CLI compatibility
  tests pass.
- No network test contacts a public target.
