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

---

### Task 1: Extend the typed canonical model for runtime fidelity

**Files:**
- Modify: `tools/corpus/model.py`
- Test: `tests/corpus/test_model_runtime_fidelity.py`

**Interfaces:**
- Consumes: existing `CanonicalRecord`, `stable_record_id()`, and `validate_record()`.
- Produces these additional `CanonicalRecord` fields:
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

- [ ] **Step 1: Write failing runtime-fidelity model tests**

Add tests that construct records with each runtime-fidelity field and assert:

```python
self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, probe_priority=99)))
self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, probe_timeout_ms=2000)))
self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, fallback_probe_ids=("B", "A"))))
self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, match_strength="soft")))
self.assertNotEqual(stable_record_id(base), stable_record_id(replace(base, probe_payload_hex="00ff")))
```

Also assert `os_features` ordering is semantic-order independent, while fallback order remains semantic:

```python
left = replace(os_record, os_features=(("TTL", "64"), ("DF", "Y")))
right = replace(os_record, os_features=(("DF", "Y"), ("TTL", "64")))
self.assertEqual(stable_record_id(left), stable_record_id(right))

ordered = replace(base, fallback_probe_ids=("HTTPGet", "GenericBanner"))
reversed_order = replace(base, fallback_probe_ids=("GenericBanner", "HTTPGet"))
self.assertNotEqual(stable_record_id(ordered), stable_record_id(reversed_order))
```

Validation tests must reject odd/non-hex payload text, negative timeout/priority/specificity, non-positive `max_response_bytes`, invalid `match_strength`, duplicate OS feature keys, and empty fallback IDs.

- [ ] **Step 2: Run corpus tests and verify RED**

Run: `make corpus-test`

Expected: FAIL because the new `CanonicalRecord` fields do not exist yet.

- [ ] **Step 3: Implement minimal typed fields, semantic normalization, and validation**

Update `_semantic_payload()` so all runtime-significant new fields affect canonical ID. Normalize `probe_payload_hex` to lowercase for semantic hashing; sort `os_features` by key for hashing; preserve tuple order for `fallback_probe_ids`.

Validation rules:

```python
probe_payload_hex is None or even-length lowercase/uppercase hex text
probe_priority is None or integer >= 0
probe_timeout_ms is None or integer > 0
fallback_probe_ids contains non-empty unique strings
match_strength is None, "hard", or "soft"
max_response_bytes is None or integer > 0
specificity is None or integer >= 0
os_features has non-empty unique keys and string values
```

Kind-specific requirements:
- `active_probe`: requires `probe_id`, `probe_payload_hex`, and `probe_timeout_ms`.
- `service_matcher`: requires `probe_id`, `matcher_type`, `matcher_expression`, `service`, and `match_strength`.
- `udp_probe`: requires `probe_id`, exactly one port, `protocol_hint`, `max_response_bytes`, and `probe_payload_hex`.
- `os_fingerprint`: requires `fingerprint_name`, `os_family`, and at least one `os_features` entry.

- [ ] **Step 4: Run corpus tests and verify GREEN**

Run: `make corpus-test`

Expected: all existing and new tests PASS.

- [ ] **Step 5: Commit**

Commit message: `feat(corpus): model runtime fidelity fields`

---

### Task 2: Extend deterministic JSONL serialization for the new fields

**Files:**
- Modify: `tools/corpus/io.py`
- Test: `tests/corpus/test_io_runtime_fidelity.py`

**Interfaces:**
- Consumes: extended `CanonicalRecord` from Task 1.
- Produces deterministic JSON representations for all runtime-fidelity fields.

- [ ] **Step 1: Write failing round-trip tests**

Create one record for each kind (`active_probe`, `service_matcher`, `udp_probe`, `os_fingerprint`) using non-default runtime fields. Write it with `write_jsonl()`, read it with `load_jsonl()`, and assert exact dataclass equality.

Assert serialized OS features are deterministic objects encoded as sorted two-element arrays:

```json
"os_features":[["DF","Y"],["TTL","64"]]
```

Assert fallback order is preserved exactly.

- [ ] **Step 2: Run corpus tests and verify RED**

Run: `make corpus-test`

Expected: FAIL because `record_to_dict()` / `record_from_dict()` do not serialize the new fields.

- [ ] **Step 3: Implement strict serializer/parser support**

Add every Task-1 field to `record_to_dict()` and `record_from_dict()`. Do not coerce strings into booleans/integers. Require `os_features` to be an array of two-string arrays and `fallback_probe_ids` to be an array of strings.

- [ ] **Step 4: Run corpus tests and verify GREEN**

Run: `make corpus-test`

Expected: all tests PASS and byte determinism remains unchanged across input order.

- [ ] **Step 5: Commit**

Commit message: `feat(corpus): serialize runtime fidelity fields`

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
- `emit_service_db(records: list[CanonicalRecord]) -> str`
- `parse_udp_db(path: Path) -> list[CanonicalRecord]`
- `emit_udp_db(records: list[CanonicalRecord]) -> str`
- `parse_os_db(path: Path, address_family: str) -> list[CanonicalRecord]`
- `emit_os_db(records: list[CanonicalRecord]) -> str`

All first-party records use provenance source `skan-first-party`, revision `repository`, license `MIT`, and deterministic `source_hash` computed from normalized logical source entry bytes, not from wall-clock metadata.

- [ ] **Step 1: Write service parser/emitter tests from current grammar**

Fixtures must cover:
- `Probe TCP` and `Probe UDP` declarations;
- rarity, priority, timeout, ports, ordered fallbacks;
- empty and binary `send` payloads;
- `match` and `softmatch`;
- matcher types `regex`, `prefix`, `suffix`, `substring`, `exact`;
- capture templates in product/version/extra/hostname/tunnel;
- escaped `\r`, `\n`, `\t`, `\\`, `\"`, and `\xNN`.

Assert `parse -> emit -> parse` produces the same semantic record list.

- [ ] **Step 2: Write UDP parser/emitter tests**

Cover the exact runtime line grammar:

```text
probe NAME PORT PROTOCOL_HINT MAX_RESPONSE_BYTES PAYLOAD_HEX
```

Assert exact preservation of port, protocol hint, response bound, and payload hex.

- [ ] **Step 3: Write OS parser/emitter tests**

Cover both IPv4 and IPv6 forms, including optional `ID`, optional `SPECIFICITY`, `Class`, scalar features, comma-valued `TCP_OPTIONS`, and range features such as `TTL_RANGE` / `WINDOW_RANGE`.

Assert unknown uppercase feature keys are preserved instead of discarded.

- [ ] **Step 4: Run corpus tests and verify RED**

Run: `make corpus-test`

Expected: import failures for the three new runtime parser modules.

- [ ] **Step 5: Implement minimal parsers/emitters**

Implement only syntax accepted by Skan's current first-party runtime files. Reject malformed, duplicate, unsupported, or lossy constructs with `ValueError` including file/line context.

- [ ] **Step 6: Run corpus tests and verify GREEN**

Run: `make corpus-test`

Expected: all parser/emitter tests PASS.

- [ ] **Step 7: Commit**

Commit message: `feat(corpus): round trip first-party runtime dbs`

---

### Task 4: Add repository round-trip equivalence gate and canonical migration command

**Files:**
- Create: `tools/corpus/migrate_first_party.py`
- Modify: `tools/corpus/validate.py`
- Modify: `GNUmakefile`
- Modify: `.github/workflows/corpus-foundation.yml`
- Test: `tests/corpus/test_first_party_migration.py`

**Interfaces:**
- `migrate_first_party(root: Path, output_root: Path) -> dict[str, object]`
- CLI: `python3 -m tools.corpus.migrate_first_party --root . --check`
- Make target: `make corpus-roundtrip`

- [ ] **Step 1: Write failing repository-level migration tests**

Tests copy the four runtime DBs to a temporary repository fixture, parse them into canonical records, emit generated DBs, parse generated DBs again, and assert semantic equality for every record.

Also assert migration is deterministic across two independent output directories and that generated DB bytes are identical across runs.

- [ ] **Step 2: Run tests and verify RED**

Run: `make corpus-test`

Expected: FAIL because migration orchestration does not exist.

- [ ] **Step 3: Implement migration orchestration**

`migrate_first_party()` must:
1. parse `data/service-probes.db`;
2. parse `data/udp-probes.db`;
3. parse `data/os-fingerprints.db` as IPv4;
4. parse `data/os-fingerprints-v6.db` as IPv6;
5. validate all canonical records against the source manifest;
6. write canonical JSONL files deterministically to the requested output root;
7. regenerate all four runtime DBs from those canonical records;
8. parse regenerated runtime DBs and require semantic equality;
9. return deterministic counts/hashes.

`--check` must use a temporary directory and never mutate repository `data/*.db` or committed canonical files.

- [ ] **Step 4: Add `corpus-roundtrip` gate**

Add:

```make
corpus-roundtrip:
	python3 -m tools.corpus.migrate_first_party --root . --check

corpus-verify: corpus-test corpus-roundtrip
	python3 -m tools.corpus.validate --root .
```

The existing corpus workflow continues to run only `make corpus-verify`.

- [ ] **Step 5: Run complete corpus verification**

Run: `make corpus-verify`

Expected: tests PASS, round-trip PASS, repository validation PASS, and no tracked runtime DB changes.

- [ ] **Step 6: Commit**

Commit message: `test(corpus): gate first-party runtime round trip`

---

### Task 5: Full Skan regression verification and PR review

**Files:**
- No production runtime file changes expected.

- [ ] **Step 1: Verify diff scope**

Confirm this branch does not modify `src/**`, `include/**`, or committed `data/*.db` runtime artifacts.

- [ ] **Step 2: Run `Fingerprint Corpus CI`**

Expected: `make corpus-verify` PASS.

- [ ] **Step 3: Run full `Skan CI`**

Required green jobs: core tests, Nmap CLI regression, repository clean, debug, release, ASan, UBSan, coverage, fuzz, benchmark, static/security audit, and privileged IPv4/IPv6 lab.

- [ ] **Step 4: Review PR diff for lossiness**

Specifically inspect that every current runtime field is represented canonically:
- service probe priority/timeout/fallback/payload;
- hard vs soft match;
- extra/hostname/tunnel templates;
- UDP response limit/protocol hint/payload;
- OS fingerprint name/native ID/specificity/arbitrary feature map.

- [ ] **Step 5: Keep the PR unmerged until explicit user approval**

No automatic merge or auto-merge.
