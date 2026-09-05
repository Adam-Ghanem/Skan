# Phase 1 TRUST — Host Reachability Consistency Plan

## Goal

Eliminate contradictions where a host is rendered as reachable from port-scan evidence while the scan summary or machine-readable output still reports that host as not up.

## Root cause

`ScanReportBuilder` preserves the discovery-stage host state even after later port-scan results prove the host responded. The terminal renderer independently treats `open`, `closed`, and `unfiltered` port results as reachability evidence, while `calculate_summary()` and JSON serialization use the stored `HostResult::state`. This allows one report to expose conflicting truths.

## Invariant

A positive transport response is authoritative reachability evidence:

- `open` => host is up
- `closed` => host is up (RST/negative response still proves reachability)
- `unfiltered` => host is up
- `filtered`, `open|filtered`, `unknown`, `error`, and `unreachable` do not by themselves prove reachability

Final reports built by the orchestrator must promote the host state to `Up` when authoritative port evidence exists.

## Task 1 — Add a regression test first (RED)

**File:** `tests/unit/orchestrator/test_scan_report_builder.cpp`

Add a case where discovery reports a target as `Unknown` (timeout), but a later TCP result for the same target is `Closed`. Assert that the built report marks the host `Up` and that `calculate_summary(report).hosts_up` reflects it.

Verification: run `make -j2 test`. The new assertion must fail against the current implementation for the expected reason.

## Task 2 — Implement the smallest source-of-truth fix (GREEN)

**File:** `src/orchestrator/scan_report_builder.cpp`

Add a small helper that recognizes authoritative port reachability evidence, then reconcile each final `HostResult::state` after port results are attached and before report sorting/return.

Do not infer reachability from timeout/filtered/error states. Do not change service or OS detection behavior.

Verification: rerun `make -j2 test`; the regression and existing suite must pass.

## Task 3 — Protect machine-readable consistency

**Files:**
- `tests/unit/output/test_output_json.cpp`
- `tests/unit/output/test_output_xml.cpp` or the existing output integration test if it already exercises the built report

Add/adjust coverage proving that a reconciled report exposes the same host-up truth in host state and summary fields. Prefer testing the report built through `ScanReportBuilder` rather than inventing a second reachability rule in serializers.

Verification: `make -j2 test` plus the existing CLI regression tests.

## Task 4 — Strengthen the privileged lab assertion

**File:** `.github/workflows/ci.yml`

Extend the existing isolated network-namespace validation to assert that Skan's final normal output does not contain a contradictory zero-up summary when an open or closed port response was observed. Keep the test inside the private documentation-range lab already used for Nmap comparison.

Verification: PR CI, especially `core-tests` and `privileged-private-lab`.

## Non-goals for this slice

Exit-code taxonomy, schema versioning, UDP production hardening, benchmark redesign, and wider Nmap compatibility are separate Phase 1/2 slices after this invariant is green.
