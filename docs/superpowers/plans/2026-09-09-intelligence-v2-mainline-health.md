# Intelligence v2 Mainline Health Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore mainline health with durable semantic OS corpus regression gates.

**Architecture:** Keep production parsing and matching unchanged. Replace corpus-size and vector-position coupling with semantic inspection helpers in the OS database test, then update stale profile identities in matcher-level tests to canonical records that exist in the expanded corpus.

**Tech Stack:** C++20, existing assert-based test executables, GNU Make, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-09-intelligence-v2-mainline-health-design.md`

## Global Constraints

- Do not copy or derive Nmap corpus data.
- Do not scan arbitrary Internet targets; this increment is offline-only.
- Do not modify production scanner behavior or matcher scoring.
- Do not replace the old count with a new fixed production corpus count.
- Preserve all existing parser rejection coverage.
- Use canonical IDs `skan-v4-linux-modern-64240` and `skan-v6-linux-modern-64240` as stable representative records.

---

### Task 1: Semantic built-in OS corpus contract

**Files:**
- Modify: `tests/unit/db/test_os_db.cpp`

**Interfaces:**
- Consumes: `db::OSFingerprintDatabase::built_in()` and `db::OSFingerprint` metadata.
- Produces: an offline regression gate independent of corpus size and record order.

- [ ] **Step 1: Establish RED.** Build and run `build/test_os_db` on the unmodified branch. Confirm the failure is the stale `built_in.fingerprints().size() == 8U` assertion.
- [ ] **Step 2: Add semantic test helpers.** Add local helpers that find a record by ID and validate non-empty/unique record identity and metadata while counting IPv4 and IPv6 records.
- [ ] **Step 3: Replace brittle assertions.** Require non-empty IPv4 and IPv6 partitions, unique names and IDs, valid families, and the two canonical representative IDs with their correct address families.
- [ ] **Step 4: Verify GREEN.** Run `make -j2 build/test_os_db && ./build/test_os_db` and confirm exit code zero.
- [ ] **Step 5: Commit.** Commit only the semantic corpus contract as `test(db): validate OS corpus semantics`.

### Task 2: Current-corpus OS behavior regressions

**Files:**
- Modify: `tests/unit/osdetect/test_os_matcher.cpp`
- Modify: `tests/unit/osdetect/test_os_scheduler.cpp`
- Modify: `tests/integration/osdetect/test_os_detection_injected.cpp`

**Interfaces:**
- Consumes: current built-in corpus and existing OS matcher/scheduler APIs.
- Produces: stable ranking assertions for `LinuxModern64240` and `IPv6LinuxModern64240`.

- [ ] **Step 1: Establish RED.** Build and run the three unmodified executables after Task 1. Record every stale-name failure exposed after `test_os_db` is fixed.
- [ ] **Step 2: Update only removed identities.** Replace `SkanLinuxGeneric` expectations with `LinuxModern64240`; replace IPv6 expectations with name `IPv6LinuxModern64240` and ID `skan-v6-linux-modern-64240`.
- [ ] **Step 3: Preserve behavioral assertions.** Keep confidence, category, address-family, lifecycle, response-count, and evidence assertions unchanged.
- [ ] **Step 4: Verify GREEN.** Run all four focused OS executables and confirm exit code zero.
- [ ] **Step 5: Commit.** Commit as `test(os): align regressions with canonical corpus IDs`.

### Task 3: Verification and delivery

**Files:**
- Modify only if a verification failure has a proven root cause and a regression test.

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces: reviewed branch, GitHub PR, and CI evidence.

- [ ] **Step 1: Run full local checks.** Run `make -j4 all test check-line-endings check-version`, debug and release builds, ASan, and UBSan in WSL.
- [ ] **Step 2: Review the full diff.** Confirm no production behavior, corpus record, generated artifact, secret, or unrelated file changed.
- [ ] **Step 3: Request independent code review.** Resolve all Critical and Important findings before delivery.
- [ ] **Step 4: Push and open PR.** Push `codex/intelligence-v2-mainline-health` and open a PR to `main` with measured test evidence.
- [ ] **Step 5: Check GitHub CI.** Wait for all required checks; fix failures using systematic debugging and TDD.
- [ ] **Step 6: Merge only when verified.** Use the development-branch finishing workflow, merge without rewriting history, and verify the resulting main SHA and CI.
