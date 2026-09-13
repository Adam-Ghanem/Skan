# Service Corpus Scale v2 Design

## Goal

Grow Skan's first-party service fingerprint coverage without trading accuracy,
safety, or provenance for a headline rule count. This milestone establishes a
data-driven validation boundary and adds a first standards-backed protocol batch.

## Authority and Trust Boundaries

- `data/service-probes.db` remains the installed runtime authority.
- `corpus/canonical/` remains its governed, deterministic mirror.
- Tests execute the production C++ parser and matcher, not a Python regex
  approximation.
- Nmap and proprietary fingerprint corpora are forbidden source material.
- Protocol behavior may be implemented clean-room from public standards and
  upstream protocol documentation.

## Fixture Contract

`tests/data/service-fingerprints-v1.tsv` is an offline response corpus. Each
non-comment line has eight tab-separated fields:

1. unique case identifier;
2. `match` or `none`;
3. probe name;
4. response bytes encoded as lowercase hexadecimal;
5. expected service or `-`;
6. expected product or `-`;
7. expected version or `-`;
8. minimum confidence in decimal form.

The test loader is fail-closed and bounded: exact field count, unique safe IDs,
known outcomes, valid even-length lowercase hex, bounded line/file/case counts,
and no ignored malformed records. Every case runs through `ServiceMatcher` with
the real runtime database.

## First Protocol Batch

- NNTP `CAPABILITIES` on TCP/119, based on RFC 3977. It is read-only and
  provides protocol/version and optional implementation evidence.
- SOCKS5 method negotiation on TCP/1080, based on RFC 1928. The greeting does
  not request a relay connection and the two-byte method reply is distinctive.
- AJP13 `CPing`/`CPong` on TCP/8009, based on Apache Tomcat's protocol reference.
- rsync daemon greeting on TCP/873, based on the upstream rsync daemon protocol.

Each family gets positive and collision-negative fixtures. Port hints affect
probe order only; response evidence remains authoritative.

## Scaling Policy

Broad coverage is measured by independently useful protocol/product families,
positive and negative fixture coverage, collision resistance, and version
extraction accuracy. A single bounded regex may safely cover thousands of real
version strings; duplicating it into thousands of cosmetic rules is prohibited.
The fixture contract supports up to 4,096 cases so future batches can scale
without changing the test architecture.

## Acceptance Criteria

- The four new probe families parse through the production loader.
- Every new family has positive and negative offline fixtures.
- Expected service/product/version/confidence are validated by the C++ matcher.
- Malformed fixture files fail closed.
- Runtime-to-canonical-to-runtime round-trip is exact and deterministic.
- No test contacts a network target.
