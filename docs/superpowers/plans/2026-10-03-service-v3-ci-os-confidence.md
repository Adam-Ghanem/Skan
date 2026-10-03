# Service V3 integration and OS evidence confidence

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Integrate the existing Service V3 changes and prevent sparse OS observations from reporting full-confidence identities.

**Architecture:** Repair the workflow configuration without weakening its validator. Retain the OS matcher and existing field weights; include unavailable fingerprint fields in the score denominator, retain evidence lists, and prevent NoMatch candidates from becoming published host identities. Prefer specific, strongly supported profiles over broad strong fallbacks.

**Tech Stack:** C++20, GNU Make, Python standard library, GitHub Actions.

**Spec:** User-approved audit in this conversation: fix CI, validate/integrate PR #81, then correct sparse OS confidence. Remaining TLS/corpus/benchmark milestones are subsequent work.

## Global Constraints

- Preserve deterministic results, explicit unsupported evidence, existing corpus bytes and output schemas.
- Never treat a match score as a calibrated probability.
- Push every completed change to GitHub; do not force-push or weaken quality gates.
- Use offline and loopback tests; retain capability skips for unavailable raw transports.

## Review Focus

- Sparse IPv4 and IPv6 observations must not become StrongMatch.
- Missing and unsupported fields must reduce support without becoming mismatches.
- Strong broad fallbacks must not hide a strongly supported specific profile.
- NoMatch candidates must remain inspectable without publishing a host identity.
- Workflow policy must validate all tracked workflows rather than suppressing its failure.

### Task 1: Workflow policy and Service V3 integration

**Files:** `.github/workflows/materialize-codex-patch.yml`.
**Interfaces:** Consume existing workflow-policy CLI; produce a policy-compliant PR #81 head.

- [ ] Reproduce `python3 scripts/validate_workflow_policy.py .github/workflows/*.yml` failing on the checkout tag and retained credentials.
- [ ] Pin checkout to the same reviewed SHA as `ci.yml`; add `persist-credentials: false`.
- [ ] Run workflow policy, its seven unit tests, full build/tests, Service V3 replay and generated-runtime gate. Expected: exit 0, with explicit environment capability skips retained.
- [ ] Commit and push to the existing PR branch. Review and merge the exact verified head.

### Task 2: Coverage-aware OS scores

**Files:** `src/osdetect/os_matcher.cpp`, `src/osdetect/os_scheduler.cpp`, `tests/unit/osdetect/test_os_matcher.cpp`, `tests/unit/osdetect/test_os_scheduler.cpp`, OS confidence documentation.
**Interfaces:** Preserve `OSMatcher::match(const ObservedOSFingerprint &, std::size_t)` and `OSDetectionResult`; revise score semantics and classification promotion.

- [ ] Add regression expectations: TTL-only IPv4/IPv6 is never StrongMatch; unsupported ACK/sequence evidence is unavailable and reduces score; adding matching evidence increases support; complete and empty observations score 1 and 0 respectively; strong specific profiles retain precedence over broad fallbacks.
- [ ] Run the matcher test against unchanged production code. Expected: assertion failure for sparse support.
- [ ] Compute matched field weight divided by total configured field weight. For two StrongMatch candidates prefer specificity, then score; otherwise prefer score, then specificity. Retain deterministic name/ID ties.
- [ ] Add scheduler regression using a fingerprint whose configured evidence is mostly unavailable. Expected before fix: published identity despite NoMatch; after fix: identity fields/category absent, candidate retained.
- [ ] Only promote candidates above the existing NoMatch category.
- [ ] Run focused tests, full suite, generated-runtime gate, CLI/output regressions and targeted sanitizer checks. Document scores as evidence support, not accuracy probabilities.
- [ ] Commit, push and review the changes; integrate only the verified exact head.

### Task 3: Final verification

- [ ] Verify remote commit SHAs, PR outcomes, workflow checks and clean local status.
- [ ] Report completed work, tests, capability limitations and the next TLS milestone without claiming the whole roadmap is complete.
