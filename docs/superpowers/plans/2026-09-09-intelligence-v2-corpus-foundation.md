# Intelligence Database v2 Foundation Implementation Plan

**Goal:** Deliver the first production-grade source-corpus contracts while leaving current runtime data authoritative.

**Spec:** `docs/superpowers/specs/2026-09-09-intelligence-v2-corpus-foundation-design.md`

## Task 1: Strict source governance

- Add RED tests for exact manifest fields, safe source IDs, disjoint data classes, immutable revision policy, snapshot policy, and attribution.
- Implement immutable `SourcePolicy` parsing and validation with typed failures.
- Add the Skan first-party source manifest without external snapshots or downloads.
- Verify focused tests and commit.

## Task 2: Versioned canonical record contract

- Add RED tests for schema version 2, required stable IDs, provenance binding, kind-specific fields, NFC text, and resource bounds.
- Implement immutable canonical records and deterministic semantic IDs covering runtime-relevant fields.
- Reject undocumented fields and incompatible versions.
- Verify focused tests and commit.

## Task 3: Bounded deterministic JSONL

- Add RED tests for deterministic ordering, exact round trip, duplicate IDs, oversized files/lines, record limits, malformed UTF-8, and non-atomic failure behavior.
- Implement streaming bounded loading and staged atomic writing.
- Add empty migration-staging stores with explicit documentation.
- Verify focused tests and commit.

## Task 4: Integration and delivery

- Add corpus targets directly to the current `Makefile`; do not add a shadow `GNUmakefile`.
- Integrate checks with current CI and packaging build dependencies.
- Run corpus tests, full C++ tests, debug/release, ASan, UBSan, workflow policy, packaging tests, diff and secret checks.
- Request independent review, push, open PR, wait for CI, merge only when green, and verify `main`.

## Next increment

Port the runtime parsers selectively, fix kind-specific OS conflict keys, and require the full `runtime DB -> canonical reload -> validation -> generated DB -> real C++ loader` contract before canonical data can become authoritative.
