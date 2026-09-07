# Fingerprint Corpus v2 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic, license-aware canonical corpus foundation that later importers (Rapid7 Recog, IANA, NVD/CPE) can safely feed without changing Skan runtime databases yet.

**Architecture:** Use Python 3 standard-library tooling under `tools/corpus/` for source-policy validation, canonical record validation, deterministic JSONL I/O, stable semantic IDs, provenance handling, snapshot integrity, deduplication/conflict reporting, and corpus statistics. Keep existing `data/*.db` authoritative in this plan; no runtime loader, matcher, scheduler, scan, or package behavior changes.

**Tech Stack:** Python 3.11+ standard library, JSON/JSONL, SHA-256, `unittest`, GNU Make, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-07-fingerprint-corpus-v2-design.md`

## Global Constraints

- Do not copy or mechanically translate Nmap fingerprint/probe databases.
- Nmap remains reference/comparator-only in this project.
- Existing `data/service-probes.db`, `data/udp-probes.db`, `data/os-fingerprints.db`, and `data/os-fingerprints-v6.db` remain authoritative in this plan.
- Use Python standard library only; add no runtime or build dependency.
- Normal validation/build paths must not fetch the network.
- External sources must be declared before use and must have explicit redistribution policy.
- Stable record IDs must depend on semantic fingerprint identity, not source identity or import order.
- Every external contribution must retain provenance and license metadata.
- Generated JSON/JSONL must be deterministic and contain no current wall-clock timestamps.
- Source snapshots must be hash-pinned before deterministic builds consume them.
- Unsafe/ambiguous input fails closed; do not silently downgrade validation failures.
- No changes to scanner runtime behavior, matcher semantics, output schemas, CLI behavior, packaging contents, or live-network behavior in this plan.

## File Structure

Create:
- `tools/corpus/__init__.py` — package marker only.
- `tools/corpus/sources.py` — source-manifest dataclass, loader, policy validation.
- `tools/corpus/model.py` — canonical record/provenance model, semantic ID generation, record validation.
- `tools/corpus/io.py` — deterministic JSON/JSONL readers/writers.
- `tools/corpus/snapshots.py` — pinned snapshot SHA-256 verification.
- `tools/corpus/dedupe.py` — semantic merge and conflict reporting.
- `tools/corpus/stats.py` — deterministic corpus statistics.
- `tools/corpus/validate.py` — repository-level validator CLI.
- `corpus/sources/sources.json` — initial source policy containing only Skan first-party baseline.
- `corpus/canonical/services.jsonl` — initially empty canonical service records.
- `corpus/canonical/os.jsonl` — initially empty canonical OS records.
- `corpus/canonical/udp.jsonl` — initially empty canonical UDP records.
- `corpus/canonical/products.jsonl` — initially empty enrichment vocabulary records.
- `corpus/overrides/aliases.json` — `{}`.
- `corpus/overrides/conflicts.json` — `{}`.
- `corpus/overrides/suppressions.json` — `{}`.
- `tests/corpus/test_sources.py`
- `tests/corpus/test_model.py`
- `tests/corpus/test_io.py`
- `tests/corpus/test_snapshots.py`
- `tests/corpus/test_dedupe.py`
- `tests/corpus/test_validate.py`

Modify:
- `Makefile` — add `corpus-test` and `corpus-verify`; make `test` depend on `corpus-test` without changing C++ build ordering.
- `.github/workflows/ci.yml` — run `make corpus-verify` in `core-tests` before the production build.

---

### Task 1: Source manifest and fail-closed license policy

**Files:**
- Create: `tools/corpus/__init__.py`
- Create: `tools/corpus/sources.py`
- Create: `corpus/sources/sources.json`
- Test: `tests/corpus/test_sources.py`

**Interfaces:**
- Produces: `SourcePolicy`, `load_source_manifest(path: Path) -> dict[str, SourcePolicy]`, `validate_source_policy(source: SourcePolicy) -> list[str]`.
- Later tasks consume source IDs and policy fields exactly from this API.

- [ ] **Step 1: Write the failing tests**

Create `tests/corpus/test_sources.py` with tests equivalent to:

```python
import json
import tempfile
import unittest
from pathlib import Path

from tools.corpus.sources import load_source_manifest


class SourceManifestTests(unittest.TestCase):
    def write_manifest(self, payload: dict) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "sources.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_loads_approved_source(self):
        path = self.write_manifest({
            "schema_version": 1,
            "sources": [{
                "id": "skan-first-party",
                "name": "Skan first-party corpus",
                "homepage": "https://github.com/Adam-Ghanem/Skan",
                "source_url": "https://github.com/Adam-Ghanem/Skan/tree/main/data",
                "license_spdx_or_policy": "MIT",
                "redistribution_allowed": True,
                "attribution_required": False,
                "approved_data_classes": ["service_matcher", "active_probe", "os_fingerprint", "udp_probe"],
                "blocked_data_classes": [],
                "pinned_revision": "repository",
                "expected_hash": None,
                "adapter": "skan_existing",
                "notes": "Repository-owned baseline data"
            }]
        })
        sources = load_source_manifest(path)
        self.assertEqual(sources["skan-first-party"].license_spdx_or_policy, "MIT")
        self.assertTrue(sources["skan-first-party"].redistribution_allowed)

    def test_rejects_duplicate_source_ids(self):
        source = {
            "id": "dup", "name": "dup", "homepage": "https://example.invalid",
            "source_url": "https://example.invalid/data", "license_spdx_or_policy": "CC0-1.0",
            "redistribution_allowed": True, "attribution_required": False,
            "approved_data_classes": ["registry"], "blocked_data_classes": [],
            "pinned_revision": "abc", "expected_hash": "sha256:" + "0" * 64,
            "adapter": "test", "notes": "fixture"
        }
        path = self.write_manifest({"schema_version": 1, "sources": [source, source]})
        with self.assertRaisesRegex(ValueError, "duplicate source id"):
            load_source_manifest(path)

    def test_rejects_redistribution_without_license(self):
        payload = {
            "schema_version": 1,
            "sources": [{
                "id": "bad", "name": "bad", "homepage": "https://example.invalid",
                "source_url": "https://example.invalid/data", "license_spdx_or_policy": "",
                "redistribution_allowed": True, "attribution_required": False,
                "approved_data_classes": ["registry"], "blocked_data_classes": [],
                "pinned_revision": "abc", "expected_hash": "sha256:" + "0" * 64,
                "adapter": "test", "notes": "fixture"
            }]
        }
        with self.assertRaisesRegex(ValueError, "license"):
            load_source_manifest(self.write_manifest(payload))
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
python3 -m unittest tests/corpus/test_sources.py -v
```

Expected: import failure because `tools.corpus.sources` does not exist.

- [ ] **Step 3: Implement the source-policy model**

Create `tools/corpus/sources.py` with:

```python
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class SourcePolicy:
    id: str
    name: str
    homepage: str
    source_url: str
    license_spdx_or_policy: str
    redistribution_allowed: bool
    attribution_required: bool
    approved_data_classes: tuple[str, ...]
    blocked_data_classes: tuple[str, ...]
    pinned_revision: str | None
    expected_hash: str | None
    adapter: str
    notes: str


def validate_source_policy(source: SourcePolicy) -> list[str]:
    errors: list[str] = []
    if not source.id.strip():
        errors.append("source id is required")
    if not source.license_spdx_or_policy.strip():
        errors.append(f"source {source.id}: license policy is required")
    if source.redistribution_allowed and not source.license_spdx_or_policy.strip():
        errors.append(f"source {source.id}: redistribution requires license policy")
    if not source.adapter.strip():
        errors.append(f"source {source.id}: adapter is required")
    if source.expected_hash is not None:
        prefix = "sha256:"
        value = source.expected_hash
        if not value.startswith(prefix) or len(value) != len(prefix) + 64:
            errors.append(f"source {source.id}: expected_hash must be sha256:<64 hex chars>")
        elif any(ch not in "0123456789abcdef" for ch in value[len(prefix):]):
            errors.append(f"source {source.id}: expected_hash must be lowercase hex")
    return errors


def load_source_manifest(path: Path) -> dict[str, SourcePolicy]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise ValueError("unsupported source manifest schema_version")
    result: dict[str, SourcePolicy] = {}
    for item in raw.get("sources", []):
        source = SourcePolicy(
            id=str(item["id"]),
            name=str(item["name"]),
            homepage=str(item["homepage"]),
            source_url=str(item["source_url"]),
            license_spdx_or_policy=str(item["license_spdx_or_policy"]),
            redistribution_allowed=bool(item["redistribution_allowed"]),
            attribution_required=bool(item["attribution_required"]),
            approved_data_classes=tuple(str(v) for v in item["approved_data_classes"]),
            blocked_data_classes=tuple(str(v) for v in item["blocked_data_classes"]),
            pinned_revision=None if item.get("pinned_revision") is None else str(item["pinned_revision"]),
            expected_hash=None if item.get("expected_hash") is None else str(item["expected_hash"]),
            adapter=str(item["adapter"]),
            notes=str(item.get("notes", "")),
        )
        if source.id in result:
            raise ValueError(f"duplicate source id: {source.id}")
        errors = validate_source_policy(source)
        if errors:
            raise ValueError("; ".join(errors))
        result[source.id] = source
    return result
```

Create `corpus/sources/sources.json` with exactly one approved source initially:

```json
{
  "schema_version": 1,
  "sources": [
    {
      "id": "skan-first-party",
      "name": "Skan first-party corpus",
      "homepage": "https://github.com/Adam-Ghanem/Skan",
      "source_url": "https://github.com/Adam-Ghanem/Skan/tree/main/data",
      "license_spdx_or_policy": "MIT",
      "redistribution_allowed": true,
      "attribution_required": false,
      "approved_data_classes": ["service_matcher", "active_probe", "os_fingerprint", "udp_probe"],
      "blocked_data_classes": [],
      "pinned_revision": "repository",
      "expected_hash": null,
      "adapter": "skan_existing",
      "notes": "Repository-owned baseline data; runtime DBs remain authoritative until round-trip migration is complete."
    }
  ]
}
```

- [ ] **Step 4: Run tests and verify GREEN**

```bash
python3 -m unittest tests/corpus/test_sources.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/corpus/__init__.py tools/corpus/sources.py corpus/sources/sources.json tests/corpus/test_sources.py
git commit -m "feat(corpus): add source policy foundation"
```

---

### Task 2: Canonical record model, provenance, and stable semantic IDs

**Files:**
- Create: `tools/corpus/model.py`
- Test: `tests/corpus/test_model.py`

**Interfaces:**
- Produces: `Provenance`, `CanonicalRecord`, `stable_record_id(record) -> str`, `validate_record(record, sources) -> list[str]`.
- `stable_record_id` returns `skan-fp-v2-` plus 24 lowercase SHA-256 hex characters.

- [ ] **Step 1: Write failing tests**

Test that two records with identical semantic fields but different provenance generate the same ID, while changing `matcher_expression` changes the ID. Also assert unknown `source_id`, missing provenance, unsupported status, confidence outside `[0.0, 1.0]`, and missing matcher expression for `service_matcher` are rejected.

Use this construction in `tests/corpus/test_model.py`:

```python
from tools.corpus.model import CanonicalRecord, Provenance, stable_record_id


def make_record(source_id: str, source_record_id: str, pattern: str = "^SSH-") -> CanonicalRecord:
    return CanonicalRecord(
        id="",
        kind="service_matcher",
        transport="tcp",
        address_family="any",
        probe_id="SSHBanner",
        probe_payload_ref=None,
        matcher_type="regex",
        matcher_expression=pattern,
        service="ssh",
        vendor=None,
        product="OpenSSH",
        version=None,
        version_info=None,
        os_family=None,
        os_generation=None,
        device_type=None,
        cpe=(),
        ports=(22,),
        rarity=1,
        confidence=0.98,
        confidence_basis="specific banner regex",
        evidence_requirements=("banner",),
        negative_constraints=(),
        provenance=(Provenance(
            source_id=source_id,
            source_record_id=source_record_id,
            source_revision="repository",
            source_url="https://github.com/Adam-Ghanem/Skan",
            source_license="MIT",
            source_hash="sha256:" + "1" * 64,
        ),),
        first_imported_revision="repository",
        last_verified_revision="repository",
        status="verified",
        notes="",
    )
```

- [ ] **Step 2: Run test and verify RED**

```bash
python3 -m unittest tests/corpus/test_model.py -v
```

Expected: import failure for `tools.corpus.model`.

- [ ] **Step 3: Implement canonical dataclasses and deterministic ID**

Use `dataclasses.dataclass(frozen=True)`. Build the semantic ID payload from these fields only:

```text
kind, transport, address_family, probe_id, probe_payload_ref,
matcher_type, matcher_expression, service, vendor, product, version,
version_info, os_family, os_generation, device_type, cpe, ports,
rarity, evidence_requirements, negative_constraints
```

Do not include `provenance`, revisions, `status`, `confidence`, `confidence_basis`, `notes`, or import order.

Serialize with:

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

Hash UTF-8 bytes with SHA-256 and return:

```python
"skan-fp-v2-" + hashlib.sha256(encoded).hexdigest()[:24]
```

Validation must enforce:
- `kind` in `{"service_matcher", "active_probe", "os_fingerprint", "udp_probe", "product_vocab", "registry"}`;
- `transport` in `{"tcp", "udp", "any", "none"}`;
- `address_family` in `{"ipv4", "ipv6", "any", "none"}`;
- `status` in `{"verified", "imported", "experimental", "suppressed", "deprecated"}`;
- `0.0 <= confidence <= 1.0` when confidence is not `None`;
- every record has at least one provenance item;
- every provenance `source_id` exists in the loaded source manifest;
- `service_matcher` requires `matcher_type`, `matcher_expression`, and `service`;
- `active_probe` requires `probe_id`;
- `os_fingerprint` requires `os_family`;
- all ports are in `0..65535` and sorted/unique at serialization time.

- [ ] **Step 4: Run test and verify GREEN**

```bash
python3 -m unittest tests/corpus/test_model.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/corpus/model.py tests/corpus/test_model.py
git commit -m "feat(corpus): add canonical fingerprint model"
```

---

### Task 3: Deterministic canonical JSONL I/O

**Files:**
- Create: `tools/corpus/io.py`
- Test: `tests/corpus/test_io.py`
- Create empty files: `corpus/canonical/services.jsonl`, `corpus/canonical/os.jsonl`, `corpus/canonical/udp.jsonl`, `corpus/canonical/products.jsonl`
- Create: `corpus/overrides/aliases.json`, `corpus/overrides/conflicts.json`, `corpus/overrides/suppressions.json`

**Interfaces:**
- Produces: `record_to_dict`, `record_from_dict`, `load_jsonl(path, sources)`, `write_jsonl(path, records)`.

- [ ] **Step 1: Write failing deterministic round-trip tests**

Test one canonical record through `write_jsonl` twice in different input orders and assert byte-identical output. Assert output is sorted by `record.id`, keys are stable, each line ends with `\n`, and loading recomputes/validates the semantic ID instead of trusting an arbitrary serialized ID.

- [ ] **Step 2: Run and verify RED**

```bash
python3 -m unittest tests/corpus/test_io.py -v
```

Expected: import failure for `tools.corpus.io`.

- [ ] **Step 3: Implement deterministic serializer**

Rules:
- use `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`;
- write records sorted by canonical ID;
- serialize tuples as JSON arrays;
- sort/deduplicate ports and CPEs;
- sort provenance by `(source_id, source_record_id, source_revision, source_hash)`;
- reject duplicate IDs during load;
- reject blank/non-object JSONL lines except empty files;
- recompute expected ID and reject mismatches.

Initialize canonical JSONL files as zero-byte files and override JSON files as exactly `{}` followed by newline.

- [ ] **Step 4: Verify GREEN and deterministic bytes**

```bash
python3 -m unittest tests/corpus/test_io.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/corpus/io.py tests/corpus/test_io.py corpus/canonical corpus/overrides
git commit -m "feat(corpus): add deterministic canonical storage"
```

---

### Task 4: Snapshot integrity verification

**Files:**
- Create: `tools/corpus/snapshots.py`
- Test: `tests/corpus/test_snapshots.py`

**Interfaces:**
- Produces: `sha256_file(path: Path) -> str`, `verify_snapshot(path: Path, expected_hash: str) -> None`.

- [ ] **Step 1: Write failing tests**

Create a temporary file containing `b"abc"`; assert `sha256_file` returns:

```text
sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Assert `verify_snapshot` accepts that hash and raises `ValueError("snapshot hash mismatch")` for a different hash.

- [ ] **Step 2: Verify RED**

```bash
python3 -m unittest tests/corpus/test_snapshots.py -v
```

- [ ] **Step 3: Implement streaming SHA-256**

Read at most 1 MiB per chunk:

```python
with path.open("rb") as handle:
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
```

No network calls belong in this module.

- [ ] **Step 4: Verify GREEN**

```bash
python3 -m unittest tests/corpus/test_snapshots.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tools/corpus/snapshots.py tests/corpus/test_snapshots.py
git commit -m "feat(corpus): verify pinned source snapshots"
```

---

### Task 5: Semantic deduplication and explicit conflict reporting

**Files:**
- Create: `tools/corpus/dedupe.py`
- Test: `tests/corpus/test_dedupe.py`

**Interfaces:**
- Produces: `merge_records(records: list[CanonicalRecord]) -> tuple[list[CanonicalRecord], list[Conflict]]` and frozen `Conflict` dataclass.

- [ ] **Step 1: Write failing tests**

Cover three cases:
1. same stable ID, same identity, different provenance => one merged record with both provenance entries;
2. same matcher context/evidence but different `product` => conflict emitted and neither record silently overwrites the other;
3. same semantic record from first-party verified and imported source => merged confidence/status selection is deterministic and provenance-complete.

- [ ] **Step 2: Verify RED**

```bash
python3 -m unittest tests/corpus/test_dedupe.py -v
```

- [ ] **Step 3: Implement merge rules**

Exact rules for this foundation:
- exact same canonical ID: merge provenance union; choose highest status rank `verified > imported > experimental > deprecated > suppressed`; choose maximum confidence; combine confidence basis as sorted unique non-empty strings joined by `"; "`; keep semantic fields unchanged;
- conflict key for matcher-like records is `(kind, transport, address_family, probe_id, matcher_type, matcher_expression, ports)`;
- if the same conflict key maps to materially different `(service, vendor, product, version, os_family, device_type)`, emit `Conflict` containing the two IDs and a sorted tuple of differing field names;
- do not automatically resolve conflicts in this module;
- return records sorted by ID and conflicts sorted by `(left_id, right_id)`.

- [ ] **Step 4: Verify GREEN**

```bash
python3 -m unittest tests/corpus/test_dedupe.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tools/corpus/dedupe.py tests/corpus/test_dedupe.py
git commit -m "feat(corpus): add deterministic dedupe and conflicts"
```

---

### Task 6: Repository validator, statistics, Makefile, and CI gate

**Files:**
- Create: `tools/corpus/stats.py`
- Create: `tools/corpus/validate.py`
- Test: `tests/corpus/test_validate.py`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces CLI:

```bash
python3 -m tools.corpus.validate --root .
```

Exit `0` means corpus foundation is valid; exit `1` means deterministic validation failure.

- [ ] **Step 1: Write failing validator tests**

Use a temporary corpus root and assert validator catches:
- unknown source reference;
- duplicate canonical ID;
- source policy error;
- malformed override JSON;
- unresolved conflicts produced by `merge_records`;
- invalid snapshot hash when a source declares a concrete `expected_hash` and its convention snapshot path exists at `corpus/snapshots/<source-id>/source`.

Also assert a root containing the initial manifest, empty canonical JSONL files, and `{}` override files validates successfully.

- [ ] **Step 2: Verify RED**

```bash
python3 -m unittest tests/corpus/test_validate.py -v
```

- [ ] **Step 3: Implement statistics and validator**

`tools/corpus/stats.py` returns a dictionary with sorted deterministic counters:

```text
total_records
records_by_kind
records_by_status
records_by_source
records_with_cpe
conflict_count
```

`tools/corpus/validate.py` must:
1. load `corpus/sources/sources.json`;
2. load all four canonical JSONL files;
3. parse all three override JSON objects;
4. validate each record against source policy;
5. run dedupe/conflict analysis;
6. reject unresolved conflicts unless the exact pair is listed in `corpus/overrides/conflicts.json` with a non-empty `resolution` string;
7. verify pinned source snapshot hashes only when `expected_hash` is non-null;
8. print one deterministic JSON summary with `sort_keys=True`;
9. never fetch the network.

- [ ] **Step 4: Add Makefile targets**

Extend `.PHONY` with `corpus-test corpus-verify` and add:

```make
corpus-test:
	python3 -m unittest discover -s tests/corpus -p 'test_*.py' -v

corpus-verify: corpus-test
	python3 -m tools.corpus.validate --root .
```

Make the existing `test` target depend on `corpus-test`:

```make
test: corpus-test $(TEST_BINARIES)
```

Do not remove or reorder the existing C++ binary executions.

- [ ] **Step 5: Add CI corpus gate**

In `.github/workflows/ci.yml`, inside `core-tests`, after `Validate privileged harness` and before `Clean production build and tests`, add:

```yaml
      - name: Validate fingerprint corpus foundation
        run: make corpus-verify
```

- [ ] **Step 6: Run focused verification**

```bash
make corpus-verify
```

Expected: all corpus unit tests PASS and validator prints a JSON summary with `"total_records": 0`.

- [ ] **Step 7: Run full production verification**

```bash
make clean
make -j2
make -j2 test
python3 scripts/validate_workflow_policy.py .github/workflows/*.yml
python3 -m unittest tests/security/test_workflow_policy.py -v
git diff --check
```

Expected: all commands PASS; runtime DB files remain byte-identical to the base revision.

- [ ] **Step 8: Commit**

```bash
git add tools/corpus/stats.py tools/corpus/validate.py tests/corpus/test_validate.py Makefile .github/workflows/ci.yml
git commit -m "ci(corpus): enforce deterministic corpus validation"
```

---

## Foundation Acceptance Gate

Before this plan is considered complete, verify all of the following:

```bash
make corpus-verify
make clean
make -j2
make -j2 test
python3 scripts/validate_workflow_policy.py .github/workflows/*.yml
python3 -m unittest tests/security/test_workflow_policy.py -v
git diff --check
```

Then verify by Git diff that none of these files changed:

```text
data/service-probes.db
data/udp-probes.db
data/os-fingerprints.db
data/os-fingerprints-v6.db
src/**
include/**
```

Expected architectural result:
- source policy is enforceable;
- canonical records have deterministic semantic IDs;
- provenance survives merges;
- snapshots can be hash-pinned;
- duplicates/conflicts are surfaced deterministically;
- corpus validation is part of CI;
- current scanner behavior and runtime databases are untouched.

## Follow-on Plans

After this foundation is verified, create separate plans in this order:
1. **Current Skan corpus migration + exact round-trip compiler** — convert the four existing runtime DBs into canonical form and reproduce loader-equivalent artifacts before making canonical data authoritative.
2. **Rapid7 Recog passive fingerprint importer** — re-verify BSD-2-Clause terms, pin a revision/snapshot, normalize only supported passive matcher semantics, quarantine unsupported regex/features.
3. **IANA registry normalization** — port/service/protocol aliases only; no identification confidence inflation.
4. **NVD/CPE enrichment** — evidence-gated vendor/product/version-to-CPE normalization using current supported NVD interfaces/snapshots.
5. **Scale/performance + controlled comparison** — tens-of-thousands corpus measurements, false-positive fixture matrix, and controlled comparison against Nmap/RustScan/Masscan without importing restricted data.
