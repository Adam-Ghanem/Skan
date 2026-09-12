# Service Detection Correctness v2 Implementation Plan

**Goal:** Make service result arbitration deterministic and prevent weak banner
guesses from being published as detected services.

**Architecture:** `ServiceMatcher` owns the canonical evidence comparison policy;
`ServiceScheduler` uses that policy while aggregating responses across probes and
applies the soft-publication confidence floor at the result boundary.

**Tech stack:** C++20, existing Make build, assertion-based unit/integration tests.

## Task 1: Characterize incorrect soft-result publication

**Files:**
- Modify: `tests/unit/detect/test_service_scheduler.cpp`

1. Add a failing test in which a generic 0.45 soft match is followed by probe
   exhaustion; require an `Unknown`/`NoMatch` result.
2. Add a failing test in which an earlier structurally stronger soft match and a
   later equal-confidence weaker match both match; require the earlier evidence.
3. Run the targeted scheduler test and confirm the new assertions fail for the
   intended reason.

## Task 2: Centralize evidence comparison

**Files:**
- Modify: `include/detect/service_matcher.hpp`
- Modify: `src/detect/service_matcher.cpp`
- Modify: `tests/unit/detect/test_service_matcher.cpp`

1. Add matcher tests for better/worse/equal result ordering.
2. Add a `service_match_is_better` pure function with deterministic tie behavior.
3. Replace the matcher's inline comparison with the function.
4. Run matcher tests.

## Task 3: Enforce scheduler result policy

**Files:**
- Modify: `include/detect/service_matcher.hpp`
- Modify: `src/detect/service_scheduler.cpp`
- Modify: `tests/unit/detect/test_service_scheduler.cpp`

1. Define the explicit soft-result publication floor.
2. Use the shared comparator across probes without replacing exact ties.
3. Publish only qualifying soft matches after probe exhaustion and on timeout.
4. Reject wrong or empty response attribution before handling every response kind.
5. Run scheduler tests and fix regressions.

## Task 4: Cross-port and regression verification

**Files:**
- Modify: `tests/unit/detect/test_service_scheduler.cpp`
- Modify if needed: `tests/integration/detect/test_service_detection_local.cpp`
- Modify if needed: `.gitattributes`

1. Add a test proving an HTTP response is accepted on port 22 when HTTP evidence
   is received from the HTTP probe.
2. Run the targeted matcher, database, scheduler, local service-detection, and
   CLI compatibility tests with timeouts.
3. Run formatting/build checks relevant to changed files and ensure canonical
   runtime manifests retain LF endings in Windows worktrees.

## Task 5: Review and delivery

1. Inspect the full diff and run secret/inappropriate-file checks.
2. Request independent code review and apply validated feedback.
3. Re-run bounded verification.
4. Create a conventional commit, push the feature branch, and open/update a PR.
5. Continue to the clean-room service-corpus expansion milestone without waiting
   for remote CI.
