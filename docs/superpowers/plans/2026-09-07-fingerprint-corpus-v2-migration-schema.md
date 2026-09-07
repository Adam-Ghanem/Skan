# Fingerprint Corpus v2 Migration Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the canonical corpus model and compiler path so Skan's existing first-party service, UDP, IPv4 OS, and IPv6 OS runtime databases can be represented and regenerated without semantic loss before third-party imports begin.

**Architecture:** Keep the current runtime loaders and `data/*.db` formats unchanged. Extend the typed canonical record only with fields required to preserve current runtime semantics, then add deterministic parsers/emitters that map existing first-party files into canonical records and back. The migration gate compares semantic parse trees rather than comments/whitespace, and generated artifacts must be deterministic.

**Tech Stack:** Python 3.12 standard library, existing `tools/corpus` package, Python `unittest`, existing C++ runtime loaders exercised by Skan CI.

**Spec:** `docs/superpowers/specs/2026-09-07-fingerprint-corpus-v2-design.md`

## Global Constraints

- Do not copy or translate Nmap fingerprint databases.
- Keep `data/*.db` authoritative until first-party round-trip equivalence is proven.
- Do not change scanner transport, scheduler, runtime matcher behavior, or output schema in this migration.
- Normal corpus verification must not require network access.
- Canonical/generated artifacts must be deterministic and contain no wall-clock timestamps.
- External data import does not start in this plan.
- Unsupported or lossy runtime constructs fail closed; they are never silently discarded.
- Runtime declaration order is semantic: service probe order participates in probe tie-breaking and per-probe rule order participates in matcher tie-breaking. Canonical migration must preserve both.

---

### Task 1: Extend the typed canonical model for runtime fidelity

**Files:**
- Modify: `tools/corpus/model.py`
- Test: `tests/corpus/test_model_runtime_fidelity.py`
- Test: `tests/corpus/test_runtime_order_fidelity.py`

**Additional `CanonicalRecord` fields:**
- `probe_payload_hex: str | None`
- `probe_priority: int | None`
- `probe_timeout_ms: int | None`
- `fallback_probe_ids: tuple[str, ...]`
- `match_strength: str | None` (`hard` or `soft`)
- `extra_template: str | None`
- `hostname_template: str | None`
- `tunnel_template: str | None`
- `protocol_hint: str | None`
- `max_response_bytes: int | None`
- `fingerprint_name: str | None`
- `fingerprint_native_id: str | None`
- `specificity: int | None`
- `os_features: tuple[tuple[str, str], ...]`
- `probe_order: int | None`
- `rule_order: int | None`

`probe_order` and `rule_order` were added after inspecting the actual C++ loader: both declaration orders can affect runtime tie-breaking and therefore must participate in the semantic ID.

- [x] Write RED runtime-fidelity model tests.
- [x] Verify RED before implementation.
- [x] Implement typed fields, semantic hashing, normalization, and fail-closed validation.
- [x] Add RED declaration-order tests and verify only those new tests fail.
- [x] Implement `probe_order` / `rule_order` semantic fidelity.
- [x] Verify corpus model suite GREEN.

Validation includes payload hex shape, priority/timeout/response bounds, fallback uniqueness/order, match strength, specificity, OS feature uniqueness, and non-negative integer declaration-order fields.

---

### Task 2: Extend deterministic JSONL serialization

**Files:**
- Modify: `tools/corpus/io.py`
- Test: `tests/corpus/test_io_runtime_fidelity.py`

- [x] Write RED round-trip tests for active probes, service matchers, UDP probes, and OS fingerprints.
- [x] Verify old tests remain green while new serialization expectations fail.
- [x] Serialize/parse every runtime-fidelity field with strict JSON types.
- [x] Preserve ordered fallbacks and declaration order; normalize OS features by key and payload hex to lowercase.
- [x] Verify byte determinism across input order.

---

### Task 3: Parse and emit Skan's current first-party runtime formats

**Files:**
- Create: `tools/corpus/runtime_service_db.py`
- Create: `tools/corpus/runtime_udp_db.py`
- Create: `tools/corpus/runtime_os_db.py`
- Test: `tests/corpus/test_runtime_service_db.py`
- Test: `tests/corpus/test_runtime_udp_db.py`
- Test: `tests/corpus/test_runtime_os_db.py`

**Interfaces:**
- `parse_service_db(path: Path) -> list[CanonicalRecord]`
- `emit_service_db(records: Iterable[CanonicalRecord]) -> str`
- `parse_udp_db(path: Path) -> list[CanonicalRecord]`
- `emit_udp_db(records: Iterable[CanonicalRecord]) -> str`
- `parse_os_db(path: Path, address_family: str) -> list[CanonicalRecord]`
- `emit_os_db(records: Iterable[CanonicalRecord]) -> str`

All first-party records use provenance source `skan-first-party`, revision `repository`, license `MIT`, and deterministic logical-record hashes. Physical source line numbers are diagnostic only and must not enter semantic/provenance hashes.

Service coverage:
- TCP/UDP probe declarations;
- rarity, priority, timeout, ports, ordered fallbacks, probe declaration order;
- empty/binary payloads and Skan escape grammar;
- hard `match` and `softmatch`;
- exact/prefix/suffix/substring/regex;
- product/version/extra/hostname/tunnel templates;
- rule declaration order.

UDP coverage:
- exact `probe NAME PORT PROTOCOL_HINT MAX_RESPONSE_BYTES PAYLOAD_HEX` grammar;
- port, protocol hint, response bound, payload, declaration order.

OS coverage:
- IPv4/IPv6;
- optional `ID`, `SPECIFICITY`, declared address family;
- `Class` metadata;
- arbitrary uppercase feature keys, including ranges and ordered option values;
- fingerprint declaration order.

- [x] Write RED parser/emitter suites and verify only the three missing modules fail.
- [x] Implement strict parsers/emitters with file/line diagnostics.
- [x] Fix provenance hashing to exclude physical line numbers.
- [x] Verify parse → emit → parse semantic equality and deterministic output GREEN.

---

### Task 4: Add real repository round-trip equivalence gate

**Files:**
- Create: `tools/corpus/migrate_first_party.py`
- Modify: `GNUmakefile`
- Test: `tests/corpus/test_first_party_migration.py`

**Interfaces:**
- `migrate_first_party(root: Path, output_root: Path) -> dict[str, object]`
- CLI: `python3 -m tools.corpus.migrate_first_party --root . --check`
- Make target: `make corpus-roundtrip`

Migration behavior:
1. parse `data/service-probes.db`;
2. parse `data/udp-probes.db`;
3. parse `data/os-fingerprints.db` as IPv4;
4. parse `data/os-fingerprints-v6.db` as IPv6;
5. validate every record against source/license/data-class policy;
6. write deterministic canonical JSONL under a requested output root;
7. regenerate all four runtime DBs;
8. parse generated DBs again and require exact semantic equality;
9. return deterministic counts and SHA-256 hashes.

`--check` always uses a temporary directory and never mutates repository runtime or committed canonical files.

- [x] Write RED repository-level migration tests against the real four runtime DBs.
- [x] Verify RED is only missing migration orchestration.
- [x] Implement migration orchestration and deterministic summary hashes.
- [x] Verify real current DB round trip GREEN: 58 service records, 7 UDP records, 3 IPv4 OS records, 5 IPv6 OS records.
- [x] Add `corpus-roundtrip` as a dependency of `corpus-verify`.
- [x] Verify `make corpus-verify` GREEN without tracked runtime/canonical mutation.

Current Make contract:

```make
corpus-roundtrip:
	python3 -m tools.corpus.migrate_first_party --root . --check

corpus-verify: corpus-test corpus-roundtrip
	python3 -m tools.corpus.validate --root .
```

The existing fingerprint-corpus workflow already runs `make corpus-verify`, so no duplicate workflow command is needed.

---

### Task 5: Full Skan regression verification and PR review

**Files:**
- No production runtime file changes expected.

- [ ] Verify diff scope contains no `src/**`, `include/**`, or committed `data/*.db` changes.
- [x] Verify `Fingerprint Corpus CI` passes the official `make corpus-verify` gate.
- [ ] Verify full `Skan CI`: core tests, Nmap CLI regression, repository clean, debug, release, ASan, UBSan, coverage, fuzz, benchmark, static/security audit, and privileged IPv4/IPv6 lab.
- [ ] Review PR diff specifically for lossiness of service priority/timeout/fallback/payload/order, hard/soft rules/templates/order, UDP bounds/hints/payload/order, and OS name/native-ID/specificity/arbitrary features/order.
- [ ] Update PR summary with RED→GREEN evidence.
- [ ] Keep PR unmerged until explicit user approval. No auto-merge.
