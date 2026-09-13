# Service Corpus Scale v2 Implementation Plan

**Goal:** Add a scalable offline fixture gate and the first clean-room protocol
expansion batch for service/version detection.

**Architecture:** The fixture harness loads `data/service-probes.db` with the
production parser and evaluates hex-encoded synthetic responses with the
production matcher. Runtime database changes are then imported into the governed
canonical mirror and verified by the existing round-trip gate.

**Tech stack:** C++20, existing Make build, Intelligence Database v2 Python
standard-library tooling.

## Task 1: Add failing runtime-corpus cases

**Files:**
- Modify: `tests/unit/detect/test_service_corpus.cpp`
- Create: `tests/data/service-fingerprints-v1.tsv`

1. Switch the corpus test from the compact built-in fallback to the real runtime
   database.
2. Implement the bounded TSV fixture reader.
3. Add positive and negative cases for NNTP, SOCKS5, AJP13, and rsyncd.
4. Run the focused test and confirm it fails because the probes are absent.

## Task 2: Add the protocol batch

**Files:**
- Modify: `data/service-probes.db`
- Modify: `docs/SERVICE_FINGERPRINTS.md`

1. Add standards-backed, read-only probe payloads and precise response matchers.
2. Keep product/version fields evidence-based and avoid port-only labels.
3. Run parser and corpus tests until green.

## Task 3: Make fixture execution a required gate

**Files:**
- Modify: `Makefile`
- Modify if needed: `.github/workflows/ci.yml`

1. Ensure the service corpus test depends on the fixture file and executes in the
   normal test suite.
2. Add malformed fixture contract tests or a deterministic self-test mode.
3. Run bounded unit and CLI regression checks.

## Task 4: Reconcile canonical authority

**Files:**
- Modify: `corpus/sources/sources.json`
- Regenerate: `corpus/canonical/*.jsonl`
- Regenerate: `corpus/canonical/manifest.json`

1. Commit the first-party runtime source batch locally to obtain an immutable Git
   revision.
2. Pin the first-party source policy and URL to that revision.
3. Run `import-runtime`, deterministic compile, and production C++ round-trip.
4. Verify a second import is byte-identical.

## Task 5: Review and delivery

1. Run secret, diff, production build, targeted service, corpus, and CLI checks.
2. Request independent review and apply validated feedback.
3. Commit the canonical reconciliation, push, and open/update the PR.
4. Merge only when locally verified and independently approved; never wait for CI.
