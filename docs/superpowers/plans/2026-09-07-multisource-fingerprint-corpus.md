# Multi-Source Fingerprint Corpus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand Skan from its small first-party corpus into a large, deterministic, legally reviewable multi-source detection and product-intelligence corpus while keeping Nmap as a benchmark/reference rather than a committed data source.

**Architecture:** Add one adapter per approved source, normalize every source into the existing canonical model, keep product/CPE metadata separate from detection evidence, fail closed on unsupported semantics/conflicts, and compile only validated records into Skan runtime data. Source refreshes are explicit and pinned; normal build/test/runtime paths remain network-free.

**Tech Stack:** Python 3 corpus tooling and tests, deterministic JSON/JSONL, XML/CSV parsing from the Python standard library, existing C++ runtime DB formats, GitHub Actions, Debian packaging checks.

**Spec:** `docs/superpowers/specs/2026-09-07-multisource-fingerprint-corpus-design.md`

## Global Constraints

- Do not copy, mechanically translate, reformat, or commit Nmap NPSL-covered fingerprint databases into Skan.
- Nmap remains comparator/reference only and never returns canonical corpus records.
- Normal `make corpus-verify`, normal package builds, and runtime scans remain network-free.
- Unknown sources, unsupported source constructs, redistribution violations, unresolved conflicts, malformed records, and missing attribution fail closed.
- Detection fingerprints and product/CPE metadata remain separate classes and separate statistics.
- Source count never automatically increases confidence.
- Keep current C++ runtime formats until measured scale requires a separately designed indexed/sharded format.
- Every externally sourced record carries pinned provenance and required attribution.

---

### Task 1: Source Locks and Refresh Framework

**Files:**
- Create: `tools/corpus/source_lock.py`
- Create: `tools/corpus/refresh.py`
- Create: `tests/corpus/test_source_lock.py`
- Create: `tests/corpus/test_refresh.py`
- Modify: `corpus/sources/sources.json`

**Interfaces:**
- Produces: `SourceLock`, `load_source_lock(path)`, `verify_snapshot(path, lock)`, `refresh_source(source_id, snapshot_path, root)`.
- Consumes: current `tools.corpus.sources` source policy and SHA-256 snapshot helpers.

- [ ] Write failing tests proving source locks require source ID, revision, source URL, SHA-256, adapter version, license policy, and attribution metadata; reject malformed hashes and unknown sources.
- [ ] Run `python3 -m unittest tests.corpus.test_source_lock tests.corpus.test_refresh -v` and confirm RED because the modules do not exist.
- [ ] Implement lock parsing/validation and a network-free refresh orchestration API that accepts an already-downloaded snapshot path.
- [ ] Re-run tests and confirm GREEN.
- [ ] Commit `feat(corpus): add pinned source lock framework`.

### Task 2: Canonical Classes for External Sources

**Files:**
- Modify: `tools/corpus/model.py`
- Modify: `tools/corpus/io.py`
- Modify: `tools/corpus/stats.py`
- Create: `tests/corpus/test_external_model.py`

**Interfaces:**
- Produces canonical kinds: `web_fingerprint`, `device_fingerprint`, `port_registry`, `product_record`, `product_alias`, `cpe_record`.
- Extends existing deterministic semantic IDs without source-bound identity.

- [ ] Write failing tests for each new kind, evidence dimensions, metadata-only classes, semantic ID stability, and JSONL round-trip.
- [ ] Run the focused tests and confirm RED.
- [ ] Add only fields required by the spec, with metadata-only records forbidden from directly carrying detection confidence/results.
- [ ] Re-run focused and full corpus tests.
- [ ] Commit `feat(corpus): extend canonical model for multisource data`.

### Task 3: Rapid7 Recog Adapter

**Files:**
- Create: `tools/corpus/adapters/__init__.py`
- Create: `tools/corpus/adapters/recog.py`
- Create: `tests/corpus/test_recog_adapter.py`
- Create: `tests/corpus/fixtures/recog/representative.xml`

**Interfaces:**
- Produces: `parse_recog_xml(text, provenance) -> list[CanonicalRecord]`.
- Rejects unsupported matcher constructs instead of approximating them.

- [ ] Write RED tests for representative service, OS/device, vendor/product/version/CPE extraction, deterministic IDs, unsupported regex/options, malformed XML, and attribution provenance.
- [ ] Implement a strict XML adapter using standard-library XML parsing; map only semantics Skan can preserve.
- [ ] Verify focused tests then full `make corpus-verify`.
- [ ] Commit `feat(corpus): import Rapid7 Recog fingerprints`.

### Task 4: IANA Services/Ports Adapter

**Files:**
- Create: `tools/corpus/adapters/iana_services.py`
- Create: `tests/corpus/test_iana_adapter.py`
- Create: `tests/corpus/fixtures/iana/service-names-port-numbers.csv`

**Interfaces:**
- Produces: `parse_iana_csv(text, provenance) -> list[CanonicalRecord]` of `port_registry` records.
- Port assignments remain weak metadata and never become product detections.

- [ ] Write RED tests for TCP/UDP/SCTP/DCCP rows, ranges, aliases, blank assignments, deterministic IDs, and the rule that registry entries carry no product-detection confidence.
- [ ] Implement strict CSV normalization.
- [ ] Run focused/full corpus verification.
- [ ] Commit `feat(corpus): import IANA service registry metadata`.

### Task 5: Deterministic External Corpus Compiler

**Files:**
- Create: `tools/corpus/compile_external.py`
- Create: `tests/corpus/test_compile_external.py`
- Modify: `GNUmakefile`
- Modify: `.github/workflows/corpus-foundation.yml`

**Interfaces:**
- Produces: `compile_external(root, source_snapshots, output_root)` and `make corpus-external-verify`.
- Merges provenance, emits conflicts, and writes deterministic normalized JSONL/stat reports.

- [ ] Write RED tests for deterministic output, duplicate provenance merge, explicit conflict files, unsupported-record rejection, and no writes to committed runtime DBs during `--check`.
- [ ] Implement compiler orchestration with current dedupe/conflict/validation primitives.
- [ ] Add CI gate using only repository fixtures/pinned local snapshots.
- [ ] Run `make corpus-verify` and `make corpus-external-verify`.
- [ ] Commit `feat(corpus): compile external fingerprints deterministically`.

### Task 6: WappalyzerGo Web Fingerprint Adapter

**Files:**
- Create: `tools/corpus/adapters/wappalyzer.py`
- Create: `tests/corpus/test_wappalyzer_adapter.py`
- Create: `tests/corpus/fixtures/wappalyzer/technologies.json`

**Interfaces:**
- Produces: `parse_wappalyzer_json(text, provenance) -> list[CanonicalRecord]` of `web_fingerprint` and `product_alias` records.
- Preserves evidence dimensions such as headers, cookies, HTML, scripts, URLs, and meta tags separately.

- [ ] Write RED tests for each evidence dimension, version extraction, categories/aliases, broad-token weak confidence, unsupported constructs, and deterministic IDs.
- [ ] Implement the strict JSON adapter.
- [ ] Verify broad rules require negative fixtures before promotion to strong/verified.
- [ ] Run full corpus verification.
- [ ] Commit `feat(corpus): add Wappalyzer web technology fingerprints`.

### Task 7: NVD CPE 2.0 Product Intelligence

**Files:**
- Create: `tools/corpus/adapters/nvd_cpe.py`
- Create: `tools/corpus/cpe_index.py`
- Create: `tests/corpus/test_nvd_cpe_adapter.py`
- Create: `tests/corpus/test_cpe_index.py`
- Create: `tests/corpus/fixtures/nvd/cpe-sample.json`

**Interfaces:**
- Produces: `parse_nvd_cpe_json(text, provenance) -> list[CanonicalRecord]` and `lookup_cpe(product_identity) -> list[CpeCandidate]`.
- CPE records provide zero detection confidence and enrich only an already detected product identity.

- [ ] Write RED tests for CPE 2.3 parsing, vendor/product/version/edition/target fields, deprecated entries, references, ambiguity-preserving lookup, and metadata-only enforcement.
- [ ] Implement streaming-friendly JSON ingestion API and deterministic compact index generation.
- [ ] Add acknowledgement/modified-data metadata required by policy.
- [ ] Run focused/full tests and report index size for fixtures.
- [ ] Commit `feat(corpus): add NVD CPE product intelligence`.

### Task 8: Attribution and Distribution Manifest

**Files:**
- Create: `corpus/THIRD_PARTY_NOTICES.md`
- Create: `tools/corpus/attribution.py`
- Create: `tests/corpus/test_attribution.py`
- Modify: `tools/corpus/validate.py`

**Interfaces:**
- Produces deterministic third-party attribution report from source locks and imported provenance.

- [ ] Write RED tests requiring Recog BSD-2 notice, Wappalyzer MIT notice, Apache/ISC notices when covered material is imported, IANA policy metadata, and NIST acknowledgement for modified NVD-derived data.
- [ ] Implement notice generation/validation.
- [ ] Gate `make corpus-verify` on notice completeness.
- [ ] Commit `chore(corpus): enforce third-party attribution`.

### Task 9: Nmap Comparator and Truth-Label Benchmark Model

**Files:**
- Create: `tools/corpus/benchmark.py`
- Create: `tests/corpus/test_benchmark.py`
- Create: `tests/corpus/fixtures/benchmark/truth.json`
- Create: `tests/corpus/fixtures/benchmark/skan.json`
- Create: `tests/corpus/fixtures/benchmark/nmap.xml`

**Interfaces:**
- Produces benchmark metrics for service accuracy, product precision/recall, exact version accuracy, device/OS accuracy, false-positive rate, ambiguity, startup/load overhead.
- Nmap parser outputs comparator observations only, never canonical records.

- [ ] Write RED tests proving Nmap observations cannot enter canonical corpus and metric calculations match hand-checked fixtures.
- [ ] Implement pure offline result parsers and metric computation.
- [ ] Add explicit claim gate function requiring precision >= Nmap, recall > Nmap, false positives <= Nmap, and recorded scanner/target/command metadata.
- [ ] Run focused/full tests.
- [ ] Commit `feat(corpus): add Nmap comparison quality gates`.

### Task 10: Active Protocol Reference Gap Registry

**Files:**
- Create: `corpus/gaps/protocols.json`
- Create: `tools/corpus/gaps.py`
- Create: `tests/corpus/test_gaps.py`

**Interfaces:**
- Produces reviewable gap tickets from benchmark observations without deriving fingerprints from Nmap signatures.

- [ ] Write RED tests for gap creation, deduplication, provenance, protocol/vendor documentation references, and explicit prohibition on Nmap database-derived matcher material.
- [ ] Implement deterministic gap registry utilities.
- [ ] Seed high-value protocol families supported by public standards and current Skan gaps, using Nerva/ZGrab2 only as permissive implementation references where applicable.
- [ ] Run full tests.
- [ ] Commit `feat(corpus): track clean-room protocol coverage gaps`.

### Task 11: Source Refresh CLI and Stats Dashboard

**Files:**
- Create: `tools/corpus/cli.py`
- Modify: `tools/corpus/stats.py`
- Create: `tests/corpus/test_cli.py`
- Modify: `GNUmakefile`

**Interfaces:**
- Produces CLI commands `verify`, `import`, `stats`, `benchmark`, `refresh-from-snapshot`.

- [ ] Write RED CLI tests covering fail-closed errors and machine-readable stats.
- [ ] Implement offline CLI around the existing modules.
- [ ] Add stats breakdown for detection vs metadata classes, suppressed records, and unresolved conflicts.
- [ ] Run corpus verification.
- [ ] Commit `feat(corpus): add multisource corpus CLI and stats`.

### Task 12: Real Source Snapshots and Large Corpus Generation

**Files:**
- Modify: `corpus/sources/sources.json`
- Create/Modify: `corpus/sources/locks/*.json`
- Modify generated: `corpus/canonical/*.jsonl`
- Modify generated: attribution/stat reports

**Interfaces:**
- Uses the implemented adapters against pinned public source revisions/snapshots.

- [ ] Pin a current Rapid7 Recog revision, import all supported machine-readable fingerprints, and record skipped/unsupported counts.
- [ ] Pin a current IANA service-name/port registry snapshot and import the complete supported registry.
- [ ] Pin a current WappalyzerGo technology dataset and import all supported patterns.
- [ ] Pin a current NVD CPE 2.0 snapshot/API export and generate the supported product/CPE intelligence index without mixing its count into detection fingerprint totals.
- [ ] Run deterministic regeneration twice and prove byte-identical outputs.
- [ ] Run dedupe/conflict analysis; resolve or explicitly suppress reviewed conflicts only.
- [ ] Commit locks + normalized corpus + notices + stats together.

### Task 13: Packaging, Performance, and Final Verification

**Files:**
- Modify packaging only if generated corpus requires explicit install entries.
- Modify CI only for verified final gates.

**Interfaces:**
- Final proof that expanded corpus remains buildable, packageable, deterministic, and within measured resource bounds.

- [ ] Run `make corpus-verify` and `make corpus-external-verify` from a clean checkout.
- [ ] Run full Skan CI: release/debug, ASan, UBSan, coverage, fuzz, benchmark, static/security, privileged private dual-stack lab, Debian package build/metadata, Debian 12 acceptance, Ubuntu 24.04 acceptance.
- [ ] Measure canonical/compiled data size, load/startup time, peak memory, and class counts.
- [ ] Run the truth-labelled Skan-vs-Nmap benchmark where the available isolated lab supports it; record results without making unsupported superiority claims.
- [ ] Confirm no Nmap NPSL database material appears in committed canonical records or generated runtime fingerprints.
- [ ] Mark PR ready only after all final gates are green; do not merge without explicit user approval.
