# Phase 1 TRUST — Host Reachability Consistency Plan

## Goal

Eliminate contradictions where a host is rendered as reachable from port-scan evidence while the scan summary or machine-readable output still reports that host as not up.

## Root cause

`ScanReportBuilder` preserves an initial host state even after later port-scan results prove the host responded. This is especially visible when discovery is disabled: the report starts the target as `Unknown`, the terminal renderer independently treats `open`, `closed`, and `unfiltered` port results as reachability evidence, while `calculate_summary()` and structured serializers consume the stored `HostResult::state`. This allows one report to expose conflicting truths.

## Invariant

A positive transport response is authoritative reachability evidence:

- `open` => host is up
- `closed` => host is up (RST/negative response still proves reachability)
- `unfiltered` => host is up
- `filtered`, `open|filtered`, `unknown`, `error`, and `unreachable` do not by themselves prove reachability

Final reports built by the orchestrator must promote the host state to `Up` when authoritative port evidence exists.

## Task 1 — Add a regression test first (RED)

**File:** `tests/unit/orchestrator/test_scan_report_builder.cpp`

Add the production-relevant case where discovery is disabled, the target begins `Unknown`, and a later TCP `Closed`/`ConnectionRefused` result proves the target responded. Assert that the built report marks the host `Up` and that `calculate_summary(report).hosts_up` reflects it.

Also keep a conservative case proving that a filtered/timeout result alone leaves the target `Unknown`.

Verification: run `make -j2 test`. The positive-response assertion must fail against the pre-fix implementation for the expected reason.

## Task 2 — Implement the smallest source-of-truth fix (GREEN)

**File:** `src/orchestrator/scan_report_builder.cpp`

Add a small helper that recognizes authoritative port reachability evidence, then reconcile each final `HostResult::state` after port results are attached and before report sorting/return.

Do not infer reachability from timeout/filtered/error states. Do not change service or OS detection behavior.

Verification: rerun `make -j2 test`; the regression and existing suite must pass.

## Task 3 — Protect machine-readable consistency

**File:** `tests/unit/orchestrator/test_scan_report_builder.cpp`

Serialize the reconciled report through JSON, XML, and grepable writers. Assert that the host state and each format's summary fields consistently report one reachable host and zero unknown hosts.

This keeps the reachability rule in the report builder instead of duplicating inference logic inside serializers.

Verification: `make -j2 test` plus the existing Nmap-compatible CLI regression tests.

## Task 4 — Strengthen the privileged lab assertion

**File:** `.github/workflows/ci.yml`

Extend the existing isolated dual-stack network-namespace validation to assert that Skan's final normal output contains `Summary: 1 hosts (1 up);` after the lab has independently verified open and closed raw TCP results against Nmap.

Keep the test inside the private documentation-range lab already used for packet capture and Nmap comparison.

Verification: PR CI, especially `core-tests` and `privileged-private-lab`.

## Non-goals for this slice

Exit-code taxonomy, schema versioning, UDP production hardening, benchmark redesign, and wider Nmap compatibility are separate Phase 1/2 slices after this invariant is green.
