# External Corpus Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate generated external intelligence from Skan's first-party runtime mirror and make every committed external count and byte cryptographically verifiable offline.

**Architecture:** Keep the four first-party runtime stores and their existing manifest in `corpus/canonical/`. Publish every generated public-source store under `corpus/external/` with a separate deterministic manifest, then verify stores, statistics, source locks, provenance, and notices as one read-only integrity boundary.

**Tech Stack:** Python 3 standard library, unittest, JSONL canonical records, GNU Make, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-27-external-corpus-integrity-design.md`

## Global Constraints

- Do not change scanner runtime behavior in this milestone.
- Do not copy or translate Nmap code or fingerprint databases.
- Do not scan public targets; validation is offline or fixture-only.
- External generation must be deterministic and network-free after inputs are supplied.
- Governed manifests, statistics, locks, notices, and stores must reject symlinks and malformed or oversized JSON.
- `corpus/canonical/` remains the first-party runtime authority; `corpus/external/` is the generated public-source authority.
- Production code follows strict RED, GREEN, REFACTOR cycles.

## Review Focus

- A stale statistics file must fail even when every JSONL record is individually valid.
- A valid store copied into the wrong authority must not be accepted as external data.
- Empty generated stores must remain manifest-bound rather than being treated as missing.
- A source lock that disagrees with record provenance must fail with the source identifier.
- A refresh run with reversed input order must produce identical store and manifest bytes.

---

### Task 1: External layout and deterministic manifest

**Files:**
- Create: `tools/corpus/external_layout.py`
- Create: `tools/corpus/external_manifest.py`
- Modify: `tools/corpus/compile_external.py`
- Modify: `tests/corpus/test_compile_external.py`

**Interfaces:**
- Produces: `EXTERNAL_KIND_FILES`, `EXTERNAL_STORE_FILES`, and `write_external_manifest(directory: Path, records_by_file: Mapping[str, Sequence[CanonicalRecord]]) -> bytes`.
- Produces: `compile_records(...)` output containing a manifest-bound `files` summary without changing record schema.

- [ ] **Step 1: Write failing manifest tests**

Add tests asserting the exact store set, canonical manifest bytes, per-file SHA-256/count/kind counts, empty-store presence, and byte-identical output when input order is reversed.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m unittest tests.corpus.test_compile_external -v`

Expected: FAIL because `manifest.json` and the public layout interfaces do not exist.

- [ ] **Step 3: Implement the layout and manifest writer**

Move the kind-to-file constants into `external_layout.py`; implement bounded deterministic manifest serialization in `external_manifest.py`; have `compile_records` publish the manifest after all JSONL stores.

- [ ] **Step 4: Run tests and verify GREEN**

Run: `python -m unittest tests.corpus.test_compile_external -v`

Expected: PASS.

### Task 2: External repository integrity verifier

**Files:**
- Create: `tools/corpus/external_integrity.py`
- Create: `tests/corpus/test_external_integrity.py`
- Modify: `GNUmakefile`

**Interfaces:**
- Consumes: `EXTERNAL_STORE_FILES` and the manifest contract from Task 1.
- Produces: `verify_external_repository(root: Path) -> dict[str, object]` and `python -m tools.corpus.external_integrity --root .`.

- [ ] **Step 1: Write failing integrity tests**

Create fixture repositories and assert success for a complete generation plus specific failures for: stale stats, missing/modified store, unknown extra JSONL store, duplicate ID across stores, provenance/lock disagreement, malformed or oversized manifest/stat/lock JSON, symlinks, and stale notices.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m unittest tests.corpus.test_external_integrity -v`

Expected: FAIL because the verifier does not exist.

- [ ] **Step 3: Implement read-only verification**

Implement strict bounded JSON readers, exact store inventory checking, external record loading, cross-store ID/conflict checks, manifest hash/count/kind validation, derivable statistics comparison, represented-source lock/provenance validation, and notice regeneration comparison. Add it to `corpus-external-verify` after the existing first-party checks.

- [ ] **Step 4: Run tests and verify GREEN**

Run: `python -m unittest tests.corpus.test_external_integrity -v`

Expected: PASS.

### Task 3: Refresh boundary and collision regression

**Files:**
- Modify: `tools/corpus/bulk_refresh.py`
- Modify: `tests/corpus/test_bulk_refresh.py`
- Modify: `.github/workflows/corpus-source-refresh.yml`

**Interfaces:**
- Consumes: Task 1 compiler output and Task 2 verification command.
- Produces: staged `<output-root>/external/` stores; the repository workflow installs only into `corpus/external/`.

- [ ] **Step 1: Write failing refresh tests**

Assert fixture refresh writes `external/manifest.json`, does not create `canonical/`, preserves a sentinel first-party `canonical/services.jsonl`, computes detection totals from the merged output, and generates identical complete outputs for reversed source file order.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m unittest tests.corpus.test_bulk_refresh -v`

Expected: FAIL because refresh currently writes `<output-root>/canonical/`.

- [ ] **Step 3: Change the refresh and workflow publication roots**

Write generated stores to `<output-root>/external/`; compare and copy that directory in the workflow; stage `corpus/external` instead of generated files in `corpus/canonical`; keep locks, stats, and notices publication unchanged.

- [ ] **Step 4: Run tests and verify GREEN**

Run: `python -m unittest tests.corpus.test_bulk_refresh tests.corpus.test_compile_external tests.corpus.test_external_integrity -v`

Expected: PASS.

### Task 4: Repository data migration and recovery

**Files:**
- Create: `corpus/external/manifest.json`
- Create: `corpus/external/services.jsonl`
- Move: `corpus/canonical/{cpe,devices,products,registry,web}.jsonl` to `corpus/external/`
- Preserve unchanged: `corpus/canonical/{active-probes,services,os,udp}.jsonl` and `corpus/canonical/manifest.json`
- Create empty governed external stores: `corpus/external/{os,products,udp,devices,cpe}.jsonl` when the moved file is not already present
- Modify: `corpus/reports/external-stats.json` only if recomputation differs
- Modify: `corpus/canonical/README.md`

**Interfaces:**
- Consumes: Task 2 verifier and the generated external service artifact from repository commit `fac5264`.
- Produces: a complete, manifest-bound `corpus/external/` generation with 2,302 service matchers, 15,522 web fingerprints, and 12,711 registry records.

- [ ] **Step 1: Demonstrate the current repository RED**

Run: `python -m tools.corpus.external_integrity --root .`

Expected: FAIL because `corpus/external/` and its manifest are absent while the statistics claim external service records.

- [ ] **Step 2: Migrate and recover governed data**

Move external web/registry and empty generated stores out of `corpus/canonical/`; recover `services.jsonl` from `fac5264`; generate the manifest from the exact committed bytes; leave the four first-party runtime stores unchanged.

- [ ] **Step 3: Verify recovered data**

Run: `python -m tools.corpus.external_integrity --root .`

Expected: PASS with `total_records=30535`, `detection_records=17824`, `service_matcher=2302`, `web_fingerprint=15522`, and `port_registry=12711`.

### Task 5: Documentation, full verification, and review

**Files:**
- Modify: `docs/INTELLIGENCE_DATABASE.md`
- Modify: `corpus/canonical/README.md`
- Modify: `README.md` only if it currently implies external records are active runtime rules

**Interfaces:**
- Consumes: completed repository layout and verification commands.
- Produces: operator/developer documentation that distinguishes committed intelligence from active scanner runtime coverage.

- [ ] **Step 1: Update documentation**

Document both authorities, offline verification, refresh publication, provenance controls, and the explicit deferral of external runtime indexing.

- [ ] **Step 2: Run targeted verification**

Run: `python -m unittest tests.corpus.test_compile_external tests.corpus.test_bulk_refresh tests.corpus.test_external_integrity tests.corpus.test_validate -v`

Expected: PASS.

- [ ] **Step 3: Run the complete corpus verification with a bounded timeout**

Run: `make -f GNUmakefile corpus-external-verify`

Expected: PASS. If the command stops making useful progress, terminate it and report the last completed check rather than waiting indefinitely.

- [ ] **Step 4: Run independent code review and fix important findings**

Review the complete branch diff against the spec, with emphasis on authority separation, parser bounds, provenance/lock equality, and generated-data accuracy.

- [ ] **Step 5: Commit and push**

Create logically scoped conventional commits, push `codex/external-corpus-integrity-v1`, and open a PR without waiting for CI.
