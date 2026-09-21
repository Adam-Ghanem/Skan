# Offline Scanner Comparison Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic, standard-library-only harness that validates operator-controlled lab scenarios, normalizes Skan JSON and Nmap XML, scores both against ground truth, and emits reproducible scorecards without sending network traffic in tests.

**Architecture:** A new `tools.comparison` package owns immutable normalized types, strict bounded input adapters, transparent metrics, deterministic reports, and opt-in process execution. Production C++ remains independent of Nmap and all automated tests use captured fixtures.

**Tech Stack:** Python 3.11+ standard library (`dataclasses`, `json`, `ipaddress`, `statistics`, `subprocess`, `xml.etree.ElementTree`, `unittest`), GNU Make

**Spec:** `docs/superpowers/specs/2026-09-20-core-superiority-foundation-design.md`

## Global Constraints

- No network access occurs during the test suite.
- Every scenario must use one literal IP target and carry `authorization: operator-controlled-lab`.
- Manifests and scanner outputs are byte-bounded before parsing.
- Duplicate JSON keys, duplicate endpoints, missing required fields, non-finite numbers, and malformed XML fail closed.
- Commands are argument vectors and runners always use `shell=False` semantics.
- Nmap is optional and never imported into production code or data.
- Reports sort all unordered data and use stable JSON formatting.

---

### Task 1: Model and validate authorized manifests

**Files:**
- Create: `tools/comparison/__init__.py`
- Create: `tools/comparison/model.py`
- Create: `tools/comparison/manifest.py`
- Create: `tests/comparison/__init__.py`
- Create: `tests/comparison/test_manifest.py`

- [x] Write tests for a minimal valid manifest plus unknown fields, duplicate IDs/endpoints, hostnames/CIDRs, missing authorization, invalid ports/states, excessive counts, oversized input, duplicate JSON keys, and non-finite timeouts.
- [x] Run `python3 -m unittest tests.comparison.test_manifest -v` and verify RED because the package does not exist.
- [x] Implement frozen model types and a strict `load_manifest(path)` with a 1 MiB file limit, schema version 1, at most 128 scenarios and 4096 total expectations.
- [x] Run the focused tests and verify GREEN.
- [x] Commit with `feat: add authorized comparison manifest`.

### Task 2: Normalize bounded Skan and Nmap results

**Files:**
- Create: `tools/comparison/parsers.py`
- Create: `tests/comparison/fixtures/skan-valid.json`
- Create: `tests/comparison/fixtures/nmap-valid.xml`
- Create: `tests/comparison/test_parsers.py`

- [x] Write tests proving equivalent normalized observations from the two fixtures, version and elapsed extraction, service evidence mapping, duplicate endpoints, malformed input, oversized input, and missing required fields.
- [x] Run `python3 -m unittest tests.comparison.test_parsers -v` and verify RED.
- [x] Implement `parse_skan_json(bytes)` and `parse_nmap_xml(bytes)` with a 4 MiB limit, at most 4096 observations, literal-IP normalization, duplicate rejection, and typed invalid-run errors.
- [x] Run the focused tests and verify GREEN.
- [x] Commit with `feat: normalize scanner comparison results`.

### Task 3: Score ground truth and emit deterministic reports

**Files:**
- Create: `tools/comparison/scoring.py`
- Create: `tools/comparison/report.py`
- Create: `tests/comparison/test_scoring.py`
- Create: `tests/comparison/test_report.py`

- [x] Write tests for full state confusion matrices, false-open counting, missing observations, service/product/version accuracy and coverage, median/p95 timing, invalid-run exclusion, stable JSON, stable Markdown, manifest digest, and an explicit no-claim result when any superiority gate fails.
- [x] Run the two focused modules and verify RED.
- [x] Implement transparent per-scanner metrics and scorecard comparison. Do not combine speed and correctness into one score.
- [x] Implement deterministic JSON/Markdown serialization and atomic report writes.
- [x] Run the focused tests and verify GREEN.
- [x] Commit with `feat: score and report scanner comparisons`.

### Task 4: Add safe opt-in orchestration and repository gate

**Files:**
- Create: `tools/comparison/commands.py`
- Create: `tools/comparison/runner.py`
- Create: `tools/comparison/cli.py`
- Create: `tests/comparison/test_commands.py`
- Create: `tests/comparison/test_runner.py`
- Modify: `Makefile`

- [x] Write tests for exact Skan/Nmap argv construction, protocol-equivalent port lists, paths/targets containing shell metacharacters remaining single argv elements, missing executables, timeouts, non-zero exits, bounded diagnostics, sequential execution, and captured-output scoring without a real scanner.
- [x] Run the focused modules and verify RED.
- [x] Implement argv builders and a live-bounded `subprocess.Popen(..., shell=False)` runner with a minimal environment and typed unavailable/timeout/error outcomes.
- [x] Implement `python3 -m tools.comparison.cli score --manifest ... --skan-json ... --nmap-xml ... --json ... --markdown ...` for offline reproducible scorecards and `run` for explicitly authorized lab execution.
- [x] Add `make test-comparison` and include it in the aggregate Python gate.
- [x] Run `make test-comparison` and `make test-corpus`; verify GREEN.
- [x] Commit with `feat: add controlled scanner comparison CLI`.

### Task 5: Final verification and documentation consistency

**Files:**
- Modify: `docs/superpowers/plans/2026-09-20-offline-comparison-foundation.md`

- [x] Run `python3 -m compileall -q tools/comparison tests/comparison`.
- [x] Run `make test-comparison`.
- [x] Run `make -j2 build/test_udp_scan && ./build/test_udp_scan`.
- [x] Run `make test-corpus`.
- [x] Run `git diff --check` and inspect the complete branch diff.
- [x] Mark this plan complete and commit the completion record.

Completion evidence: 33 comparison tests, the UDP unit binary, and 101 corpus
tests passed. Independent review findings were addressed in `419f398`, including
fail-closed claim gating, strict Nmap `extraports` handling, undeclared endpoint
rejection, live-bounded child output, report-pair rollback, and equivalent Nmap
DNS/ARP behavior.
