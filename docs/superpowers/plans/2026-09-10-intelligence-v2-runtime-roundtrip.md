# Intelligence Database v2 Runtime Round-Trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate Skan's reviewed runtime corpus into canonical v2 and prove deterministic compilation through the real C++ database loaders.

**Architecture:** A standard-library-only Python importer mirrors Skan's bounded runtime grammars, while a deterministic compiler emits the existing project-owned formats after whole-corpus validation. Python semantic round-trip tests and a C++ loader acceptance executable form the migration gate; production runtime selection does not change.

**Tech Stack:** Python 3 standard library, C++20, Make, existing Skan database loaders, `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-10-intelligence-v2-runtime-roundtrip-design.md`

## Global Constraints

- Do not copy or derive Nmap or proprietary code, formats, or corpus data.
- Perform no network access, dynamic adapter execution, or shell execution from corpus tooling.
- Preserve current scanner runtime behavior and packaged `data/*.db` selection.
- Parse untrusted input fail-closed with explicit resource bounds.
- Use Python standard library only for build-time corpus tooling.
- Publish deterministic LF-terminated UTF-8 artifacts and SHA-256 manifests.
- Follow red-green-refactor for every behavioral change.

---

### Task 1: Service runtime importer

**Files:**
- Create: `tools/corpus/runtime.py`
- Create: `tests/corpus/test_runtime.py`
- Modify: `tools/corpus/model.py`
- Modify: `tests/corpus/test_model.py`

**Interfaces:**
- Consumes: `SourcePolicy`, `CanonicalRecord`, `stable_record_id()`.
- Produces: `RuntimeCorpusError`, `ImportContext`, and `parse_service_runtime(text: bytes, context: ImportContext) -> tuple[CanonicalRecord, ...]`.

- [x] **Step 1: Write failing tests.** Cover one TCP probe, payload bytes, hard and soft matchers, binary and textual regex patterns, declaration/rule order, ports, timeout, fallbacks, provenance hashes, and rejection of unknown directives, malformed quotes, duplicate names, missing payloads, unresolved fallbacks, and over-limit input.
- [x] **Step 2: Verify RED.** Run `python3 -m unittest tests.corpus.test_runtime.RuntimeServiceImportTests -v` and confirm import failure because `tools.corpus.runtime` does not exist.
- [x] **Step 3: Implement the bounded service tokenizer and importer.** Mirror the existing Skan escape grammar, retain runtime bytes as lowercase hexadecimal where text is unsafe, and create stable source record IDs from file, probe name, and rule order.
- [x] **Step 4: Verify GREEN.** Run the focused tests and the complete corpus suite.
- [x] **Step 5: Commit.** Commit as `feat(corpus): import service runtime records`.

### Task 2: UDP and OS runtime importers

**Files:**
- Modify: `tools/corpus/runtime.py`
- Modify: `tests/corpus/test_runtime.py`

**Interfaces:**
- Consumes: `ImportContext` and canonical body types.
- Produces: `parse_udp_runtime(text: bytes, context: ImportContext) -> tuple[CanonicalRecord, ...]` and `parse_os_runtime(text: bytes, address_family: str, context: ImportContext) -> tuple[CanonicalRecord, ...]`.

- [x] **Step 1: Write failing tests.** Cover ordered UDP records and the required port-zero default; cover IPv4/IPv6 metadata, class fields, all supported typed OS operators, source block hashes, and duplicate/unknown/mixed-family failures.
- [x] **Step 2: Verify RED.** Run the two new focused test classes and confirm missing API failures.
- [x] **Step 3: Implement minimal bounded parsers.** Reuse strict helpers, map every current OS directive to the canonical field/operator/value representation, and reject any syntax not accepted by the schema.
- [x] **Step 4: Verify GREEN.** Run focused tests and `make test-corpus`.
- [x] **Step 5: Commit.** Commit as `feat(corpus): import udp and os runtime records`.

### Task 2b: Reconcile the merged UDP vertical slice

**Files:**
- Modify: `tools/corpus/legacy_udp.py`
- Modify: `tests/corpus/test_legacy_udp.py`

**Interfaces:**
- Preserves: `parse_legacy_udp()`, `load_legacy_udp()`, `compile_legacy_udp()`, and the merged real C++ UDP loader gate.
- Consolidates: the legacy compatibility API delegates parsing to `parse_udp_runtime()` while retaining its existing imported-status contract.

- [x] **Step 1: Write a failing typed-error regression.** Prove that a line-bounded huge decimal cannot leak built-in `ValueError` from the merged parser.
- [x] **Step 2: Verify RED.** Run the focused legacy UDP test and confirm the public compatibility boundary leaks the wrong exception.
- [x] **Step 3: Consolidate parser ownership.** Delegate the legacy compatibility API to the bounded unified runtime importer, translate typed errors, preserve semantic IDs/status, and retain `compile_legacy_udp()` as the single UDP emitter used by Task 3.
- [x] **Step 4: Verify GREEN.** Run focused legacy/runtime tests, the real C++ UDP loader test on Linux, and the complete corpus suite.
- [x] **Step 5: Commit.** Commit as `refactor(corpus): unify udp runtime parsing`.

### Task 3: Deterministic compiler and whole-corpus validation

**Files:**
- Create: `tools/corpus/compiler.py`
- Create: `tests/corpus/test_compiler.py`

**Interfaces:**
- Consumes: validated canonical records from all four stores.
- Produces: `CompiledCorpus`, `validate_runtime_graph(records)`, `compile_corpus(records) -> CompiledCorpus`, and `write_compiled_corpus(output_dir, compiled)`.

- [x] **Step 1: Write failing tests.** Assert exact LF bytes for synthetic service, UDP, IPv4 OS, and IPv6 OS artifacts; compile-twice equality; atomic failure preservation; manifest hashes; and failures for unresolved matchers/fallbacks, cross-transport fallbacks, duplicate names/ports/runtime IDs, missing UDP default, non-verified status, and incomplete record kinds.
- [x] **Step 2: Verify RED.** Run `python3 -m unittest tests.corpus.test_compiler -v` and confirm the compiler API is missing.
- [x] **Step 3: Implement whole-corpus validation and deterministic emitters.** Sort probes and UDP entries by declaration order, matcher rules by rule order, OS records by runtime ID, encode unsafe bytes with Skan-compatible escapes, validate all artifacts before staging, and publish `manifest.json` last.
- [x] **Step 4: Verify GREEN.** Run focused compiler tests and the complete corpus suite.
- [x] **Step 5: Commit.** Commit as `feat(corpus): compile deterministic runtime artifacts`.

### Task 4: Repository migration and semantic round-trip command

**Files:**
- Create: `tools/corpus/cli.py`
- Create: `tests/corpus/test_cli.py`
- Populate: `corpus/canonical/active-probes.jsonl`
- Populate: `corpus/canonical/services.jsonl`
- Populate: `corpus/canonical/os.jsonl`
- Populate: `corpus/canonical/udp.jsonl`
- Modify: `tests/corpus/test_io.py`

**Interfaces:**
- Consumes: source manifest, runtime importers, JSONL I/O, and compiler.
- Produces: `python3 -m tools.corpus.cli import-runtime`, `compile`, and `verify-roundtrip`.

- [x] **Step 1: Write failing CLI tests.** Use temporary directories to assert deterministic import, compile, semantic-ID equality after re-import, safe refusal of partial/missing inputs, useful stderr, and non-zero status without traceback for expected validation failures.
- [x] **Step 2: Verify RED.** Run `python3 -m unittest tests.corpus.test_cli -v` and confirm the module is absent.
- [x] **Step 3: Implement the CLI and migrate the reviewed corpus.** Import only `data/service-probes.db`, `data/udp-probes.db`, `data/os-fingerprints.db`, and `data/os-fingerprints-v6.db` under the pinned first-party policy, then write the four canonical stores.
- [x] **Step 4: Verify GREEN and determinism.** Run the CLI round-trip twice and require a clean Git diff on the second run.
- [x] **Step 5: Commit.** Commit as `feat(corpus): migrate first-party runtime database`.

### Task 5: Real C++ loader gate, CI, and documentation

**Files:**
- Create: `tests/integration/corpus/test_compiled_runtime.cpp`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/INTELLIGENCE_DATABASE.md`
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: `build/corpus-runtime/*.db` from `tools.corpus.cli compile`.
- Produces: `make test-corpus-runtime`, which compiles artifacts, loads them with the production C++ loaders, and verifies counts plus representative service, UDP, IPv4, and IPv6 semantics.

- [x] **Step 1: Write the failing C++ integration test and Make target.** Confirm the target fails before generated artifacts and build rules exist.
- [x] **Step 2: Implement the minimal build wiring.** Generate artifacts before executing the loader test and add the gate to CI without removing existing scanner coverage.
- [x] **Step 3: Document the lifecycle.** State which corpus is authoritative, how to import/compile/verify offline, source governance rules, and the explicit runtime-switch deferral.
- [ ] **Step 4: Run verification.** Execute `make test-corpus-runtime`, `make test`, CLI regression, debug/release builds, ASan, UBSan, workflow policy, packaging guards, line-ending check, `git diff --check`, and secret/prohibited-API scans.
- [ ] **Step 5: Request independent review, fix valid findings, commit, push, open a PR, and let CI continue asynchronously.** Commit as `ci(corpus): enforce runtime round-trip gate`.
