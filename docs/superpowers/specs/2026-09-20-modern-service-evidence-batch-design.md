# Modern Service Evidence Batch Design

**Date:** 2026-09-20
**Status:** Approved through the operator's autonomous “go” instruction
**Parent:** `docs/superpowers/specs/2026-09-20-core-superiority-foundation-design.md`

## Purpose

Improve Skan's service/version accuracy on modern infrastructure without
inflating the corpus with port-name guesses or weak banner fragments. This
increment adds three read-only, standards-documented HTTP probes and hardens
four existing cloud-native matchers against isolated-token false positives.

## Scope

The new probe families are:

- Prometheus `GET /api/v1/status/buildinfo` on TCP/9090;
- Grafana `GET /api/health` on TCP/3000;
- Vault-compatible `GET /v1/sys/health` on TCP/8200.

The existing ClickHouse, Docker, Kubernetes, and Matrix matchers are tightened.
Every identity requires a syntactically valid HTTP response plus
service-specific evidence. A port hint affects scheduling only and never
creates a match.

## Evidence Rules

Prometheus requires a successful HTTP response, the Prometheus success envelope,
and build-information fields. Grafana requires a successful HTTP response plus
the documented `commit`, `database`, and `version` health fields.
Vault-compatible detection accepts the documented health status codes and
requires the health tuple `initialized`, `sealed`, `server_time_utc`, and
`version`. The product label is `Vault-API`, not `HashiCorp-Vault`, because
compatible implementations can expose the same public API.

For existing probes, standalone strings such as `gitVersion`,
`Docker-Experimental`, `X-ClickHouse-`, `M_UNRECOGNIZED`, or `Synapse`
must not match. Their fallback rules must be anchored to an HTTP status line
and retain protocol-specific structure.

## Authority and Safety

- The runtime authority remains `data/service-probes.db`.
- All payloads are read-only GET requests with `Connection: close`.
- No authentication, credential guessing, state change, public-target traffic,
  Nmap corpus import, or proprietary fingerprint material is introduced.
- Primary behavior references are the official Prometheus HTTP API, Grafana
  Health API, and Vault system-health API.
- Responses and the database remain bounded by the existing production limits.

## Tests

`tests/data/service-fingerprints-v1.tsv` gains version-positive, generic
positive, and collision-negative cases for every changed family. Tests execute
the production C++ parser and matcher. Probe-order tests prove each dedicated
port schedules its specific probe before generic HTTP probes. The canonical
Intelligence Database v2 mirror is regenerated only after the runtime corpus
passes focused tests.

## Acceptance Criteria

- Prometheus, Grafana, and Vault-compatible version responses produce the
  expected service, product, version, and confidence.
- Near-miss JSON and isolated vendor tokens remain unmatched.
- ClickHouse, Docker, Kubernetes, and Matrix keep valid detections while their
  isolated-token collision cases stop matching.
- TCP/9090, TCP/3000, and TCP/8200 schedule the dedicated probe first.
- Runtime-to-canonical-to-runtime verification is semantically exact through
  the production loaders, and repeated canonical compilation is byte-stable.
  The compiled artifact is intentionally canonicalized and need not preserve
  comments or hand-authored whitespace from the runtime source.
- Focused service tests, the Python corpus suite, and registered non-privileged
  regression tests pass; environmental privileged failures are reported rather
  than hidden.

## Deferred Work

TLS application identification, HTTP/2/gRPC negotiation, broad port-speed
optimization, and superiority claims remain separate measured milestones.
