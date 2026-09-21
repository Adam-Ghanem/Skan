# Versioned Comparison Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task.

**Goal:** Add an offline, hash-bound, multi-scenario comparison bundle so future
top-1000 TCP lab results can be reproduced and audited without rerunning scans.

**Architecture:** `tools.comparison.baseline` validates a strict descriptor,
confines artifact paths to its bundle root, verifies bounded bytes by SHA-256,
and returns the existing manifest plus normalized scanner runs. The CLI feeds
those results into the existing scorer and atomic report writer. The current
claim gate remains fail-closed.

**Tech Stack:** Python 3.11+ standard library, `unittest`, existing comparison
parsers/scoring/reporting

**Spec:** `docs/superpowers/specs/2026-09-20-versioned-comparison-baseline-design.md`

## Global Constraints

- No test or verification command launches a scanner or performs network I/O.
- Every external artifact is bounded, hash-verified, and path-confined before
  parsing.
- Unknown fields, duplicate keys, duplicate paths, and incomplete coverage fail
  closed.
- Synthetic fixtures never masquerade as measured lab evidence.
- No superiority claim is enabled by this schema-v1 milestone.

### Task 1: Define the strict bundle contract

**Files:**
- Create: `tools/comparison/baseline.py`
- Create: `tests/comparison/test_baseline.py`
- Create: `tests/comparison/fixtures/baseline-v1/**`

- [x] Write RED tests for valid multi-scenario loading, stable metadata, exact
  scenario coverage, hash mismatches, unknown/duplicate fields, duplicate
  artifact paths, traversal, absolute paths, and symlink escape.
- [x] Run `python3 -m unittest tests.comparison.test_baseline -v` and verify the
  expected import/test failures.
- [x] Implement frozen bundle types plus strict bounded descriptor, path, hash,
  environment, and coverage validation.
- [x] Run the focused tests and verify GREEN.
- [x] Commit with `feat: verify versioned comparison bundles`.

### Task 2: Add offline multi-scenario CLI verification

**Files:**
- Modify: `tools/comparison/cli.py`
- Modify: `tools/comparison/__init__.py`
- Modify: `tests/comparison/test_runner.py`

- [x] Write a RED CLI test that verifies the checked-in bundle, includes every
  scenario and deterministic bundle metadata, keeps the claim closed, and
  proves `run_suite` is not called.
- [x] Add `verify-baseline --bundle --json --markdown` using the bundle loader,
  existing scorer, and atomic report writer.
- [x] Run the focused CLI and baseline tests and verify GREEN.
- [x] Commit with `feat: add offline baseline verification`.

### Task 3: Document and verify the milestone

**Files:**
- Create: `docs/COMPARISON_BASELINES.md`
- Modify: `docs/superpowers/plans/2026-09-20-versioned-comparison-baseline.md`

- [x] Document the bundle layout, hash-generation workflow, offline command,
  synthetic-fixture warning, and the still-closed superiority gate.
- [x] Run `python3 -m compileall -q tools/comparison tests/comparison`.
- [x] Run `make test-comparison`, `make test-corpus`, and
  `make test-corpus-runtime`.
- [x] Attempt the full `make -j2 test`; record any environment-only limitation.
- [x] Run `git diff --check`, inspect the branch diff, and request independent
  final review.
- [x] Address review findings, rerun affected gates, and mark this plan complete.

## Completion Evidence

- 46 comparison tests pass, including deterministic bundle-root and child-path
  swap regressions, non-blocking FIFO rejection, structured scenario evidence,
  metadata hardening, and offline CLI coverage.
- 101 corpus tests and the compiled runtime roundtrip pass.
- `python3 -m compileall -q tools/comparison tests/comparison` and
  `git diff --check` pass.
- Independent final review of `34e6e31..b90429f` reports no Critical,
  Important, or Minor findings and confirms stable file-descriptor counts.
- The aggregate `make -j2 test` passes every test reached through the changed
  comparison/service areas, then stops at `test_interface_types` line 73 because
  this sandbox cannot complete interface enumeration. This is recorded as an
  environment limitation, not a green aggregate suite.
- Schema-v1 required-profile and quality gates remain closed. This milestone
  does not make a Skan-over-Nmap superiority claim.
