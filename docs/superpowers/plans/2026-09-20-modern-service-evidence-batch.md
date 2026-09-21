# Modern Service Evidence Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add high-confidence Prometheus, Grafana, and Vault-compatible version detection while eliminating weak cloud-native token matches.

**Architecture:** Keep the existing declarative service database and production matcher. Drive changes through bounded offline response fixtures, then reconcile the authoritative runtime database into the canonical Intelligence Database v2 mirror.

**Tech Stack:** C++20 production parser/matcher, Skan service-probe DSL, Python 3 standard-library corpus tooling, GNU Make

**Spec:** `docs/superpowers/specs/2026-09-20-modern-service-evidence-batch-design.md`

## Global Constraints

- Runtime authority remains `data/service-probes.db`.
- Only read-only HTTP GET probes are allowed.
- Port hints may order probes but may not identify services.
- No Nmap or proprietary fingerprint data may be copied.
- Product/version fields require response evidence.
- Existing 1 MiB database and 8 KiB response limits remain unchanged.

## Review Focus

- A JSON body containing only `gitVersion`, `version`, or `database` must not identify a service.
- A vendor token without an HTTP status line must not identify ClickHouse, Docker, Kubernetes, Matrix, Prometheus, Grafana, or Vault.
- Vault standby, sealed, and uninitialized documented status codes must still permit evidence-based identification.
- Dedicated ports 3000, 8200, and 9090 must schedule their product probe before `HTTPGet`.
- Canonical output must compile to production-loader-equivalent semantics, and
  repeated compilation must be byte-stable; source comments and formatting are
  not part of the runtime semantic contract.

---

### Task 1: Establish failing modern-service fixtures

**Files:**
- Modify: `tests/data/service-fingerprints-v1.tsv`

**Interfaces:**
- Consumes: the eight-column fixture contract loaded by `test_service_corpus`
- Produces: positive and collision-negative production-matcher cases

- [ ] **Step 1: Add RED fixtures.** Add HTTP responses for Prometheus build info, Grafana health, and Vault health with exact service/product/version expectations. Add valid and near-miss cases for ClickHouse, Docker, Kubernetes, and Matrix. Encode bytes as lowercase hexadecimal and keep every negative expectation as `- - - 0.00`.
- [ ] **Step 2: Verify RED.** Run `make -j2 build/test_service_corpus && ./build/test_service_corpus`. Expected: failure naming the first absent new probe or the first weak collision.
- [ ] **Step 3: Confirm fixture integrity.** Run a short Python validation that every non-comment line has eight tab-separated fields and every hex field decodes.
- [ ] **Step 4: Commit fixtures.** Commit only the failing fixture additions as `test: define modern service evidence cases`.

### Task 2: Implement the runtime probe batch and hardening

**Files:**
- Modify: `data/service-probes.db`
- Modify: `tests/unit/detect/test_service_db.cpp`
- Modify: `docs/SERVICE_FINGERPRINTS.md`

**Interfaces:**
- Consumes: existing `Probe`, `send`, and bounded `match type=regex` DSL
- Produces: `PrometheusBuildInfo`, `GrafanaHealth`, and `VaultHealth` definitions plus hardened existing rules

- [ ] **Step 1: Add scheduling assertions.** In `test_service_db.cpp`, load the production database and assert that ports 9090, 3000, and 8200 select their dedicated probe first.
- [ ] **Step 2: Verify scheduling RED.** Build and run `build/test_service_db`. Expected: an assertion fails because the named probes do not exist.
- [ ] **Step 3: Add minimal probes.** Add the three read-only GET payloads and anchored, multi-field regex rules. Capture only versions present in the response.
- [ ] **Step 4: Harden existing rules.** Replace the five standalone substring fallbacks for ClickHouse, Docker, Kubernetes, Matrix error, and Synapse with HTTP-anchored structured regex rules.
- [ ] **Step 5: Document evidence.** Update the family count, primary references, and an auditable table of endpoint facts and Skan-authored evidence.
- [ ] **Step 6: Verify GREEN.** Run `make -j2 build/test_service_corpus build/test_service_db && ./build/test_service_corpus && ./build/test_service_db`. Expected: both exit 0.
- [ ] **Step 7: Commit runtime behavior.** Commit runtime, tests, fixtures, and docs as `feat: add modern service evidence batch`.

### Task 3: Reconcile the canonical corpus

**Files:**
- Modify: `corpus/sources/sources.json`
- Regenerate: `corpus/canonical/services.jsonl`
- Regenerate: `corpus/canonical/manifest.json`
- Modify if required by explicit counts: `tests/corpus/test_runtime.py`

**Interfaces:**
- Consumes: the committed first-party runtime revision
- Produces: a pinned, governed canonical mirror that compiles to semantically
  equivalent, deterministic runtime artifacts

- [ ] **Step 1: Pin provenance.** Set `source_url` and `pinned_revision` to the full hash of Task 2's runtime commit.
- [ ] **Step 2: Import deterministically.** Run `python3 -m tools.corpus.cli import-runtime --discard-history` and update only count assertions proven stale by the added matchers.
- [ ] **Step 3: Verify round trip.** Run `make -j2 test-corpus-runtime`. Expected: deterministic canonical compilation and the production C++ semantic runtime-loader gate both exit 0.
- [ ] **Step 4: Verify Python corpus rules.** Run `make test-corpus`. Expected: all tests pass.
- [ ] **Step 5: Commit reconciliation.** Commit source policy, canonical outputs, and count updates as `data: reconcile modern service evidence corpus`.

### Task 4: Regression verification

**Files:**
- Modify only when a failing test demonstrates a regression in this milestone's scope.

**Interfaces:**
- Consumes: the completed runtime and canonical corpus
- Produces: fresh verification evidence

- [ ] **Step 1: Run focused detection tests.** Run `make -j2 build/test_service_matcher build/test_service_scheduler build/test_service_detector build/test_service_corpus build/test_service_db`, then execute all five binaries.
- [ ] **Step 2: Run comparison and corpus suites.** Run `make test-comparison && make test-corpus`.
- [ ] **Step 3: Run the registered suite.** Run `make -j2 test`; report any capability/sandbox-specific failure by exact test name.
- [ ] **Step 4: Run repository checks.** Run `git diff --check b76b4db..HEAD && git status --short`.
- [ ] **Step 5: Record completion.** Update this plan's checkboxes and commit the evidence note only if it adds durable information.
