# Skan Fingerprint Corpus v2 — Design

Date: 2026-09-07
Status: Draft for user review; architecture direction approved in chat; implementation not started
Branch: `codex/fingerprint-corpus-v2-design`

## 1. Purpose

Skan’s current first-party fingerprint corpus is intentionally small. The goal of Fingerprint Corpus v2 is to turn that data layer into a large, maintainable, legally clean, evidence-backed identification corpus for service, product, version, operating-system, device, protocol, and CPE classification.

The objective is not to create the largest file. The objective is to maximize useful coverage while controlling false positives, preserving source provenance, keeping runtime behavior deterministic, and preventing incompatible third-party data from contaminating Skan’s distribution terms or implementation lineage.

This design is independent from the current TRUST PR stack. It can be reviewed now and implemented after the TRUST work is stable.

## 2. Goals

1. Build a Skan-managed canonical fingerprint corpus that can grow from tens of entries to tens of thousands or more.
2. Import only data whose redistribution/use terms are explicitly compatible with Skan’s distribution model.
3. Preserve provenance, license, source revision, and source hash for every imported record.
4. Keep Nmap as a behavioral/reference comparator unless separate permission explicitly allows data reuse.
5. Merge project-authored fingerprints with permissively licensed public datasets without losing source identity.
6. Normalize service names, vendors, products, versions, device classes, operating systems, and CPE identifiers.
7. Deduplicate equivalent fingerprints and resolve conflicting evidence deterministically.
8. Reject dangerous, unbounded, ambiguous, or low-quality patterns before they reach runtime.
9. Generate deterministic runtime database artifacts consumed by Skan’s existing loaders initially.
10. Add measurable corpus-quality, performance, and regression gates to CI.

## 3. Non-goals

- Copying `nmap-service-probes`, `nmap-os-db`, NSE scripts, or other Nmap data into Skan.
- Claiming service/OS parity with Nmap based only on record count.
- Bundling a vulnerability database or turning service detection into a vulnerability scanner in this project.
- Blindly importing active network probes from third-party sources.
- Accepting an entry only because it comes from a large or popular dataset.
- Replacing the scanner runtime, scheduler, transport, or output architecture as part of this corpus project.

## 4. Source policy

Every source is classified before ingestion.

### Tier A — Skan verified first-party

Project-authored probes, matchers, fixtures, and fingerprints that are developed and tested in Skan.

Priority: highest.

Requirements:
- owned by or contributed to Skan under the repository contribution/license terms;
- positive fixture;
- negative fixture when the pattern could overlap common protocols;
- explicit confidence and evidence class.

### Tier B — permissively reusable fingerprint datasets

Examples include datasets whose license explicitly permits redistribution and modification, such as Rapid7 Recog under BSD-2-Clause.

Requirements:
- license identifier recorded;
- source repository/release/revision recorded;
- attribution preserved when required;
- importer must transform into Skan’s canonical model rather than treating the upstream syntax as a runtime contract;
- imported entries remain traceable to every original source that contributed to the canonical record.

### Tier C — authoritative factual registries

Examples include IANA protocol/service registries, which are intended for broad reuse and whose protocol registry data is covered by CC0.

Use:
- canonical service/port/protocol naming;
- aliases;
- registry status;
- protocol metadata.

Registry metadata does not become a high-confidence version fingerprint by itself.

### Tier D — public product/CPE vocabulary

NIST/NVD public product identification data may be used for CPE normalization and product vocabulary where applicable.

Use:
- vendor/product canonicalization;
- CPE mapping/enrichment;
- version vocabulary normalization.

NVD/CPE records do not by themselves prove that a live network response belongs to a product. Detection must still come from Skan evidence.

The adapter must use currently supported NVD/CPE interfaces at implementation time. Deprecated NVD 1.0/1.1 feed assumptions and legacy XML CPE feed assumptions are not part of this design.

### Reference-only sources

Nmap remains reference-only by default. Nmap’s NPSL contains terms and compatibility constraints that make direct inclusion of its databases inappropriate for Skan’s normal corpus path without a separate explicit permission or compatible redistribution arrangement.

Allowed use:
- capability research;
- controlled behavioral comparison;
- coverage-gap analysis;
- designing independent test cases and first-party fingerprints from independently obtained protocol behavior.

Disallowed default use:
- copying signatures;
- translating Nmap fingerprint records mechanically into Skan records;
- committing Nmap database content into Skan;
- deriving a Skan matcher from Nmap text in a way that preserves the original expressive content.

## 5. Repository layout

The proposed layout is:

```text
corpus/
  sources/
    sources.json
  canonical/
    services.jsonl
    os.jsonl
    udp.jsonl
    products.jsonl
  snapshots/
    <source-id>/
  fixtures/
    services/
    os/
    udp/
  overrides/
    aliases.json
    conflicts.json
    suppressions.json

tools/corpus/
  import_recog.py
  import_iana.py
  import_nvd_cpe.py
  normalize.py
  validate.py
  dedupe.py
  compile.py
  audit_licenses.py
  stats.py

data/
  service-probes.db
  os-fingerprints.db
  os-fingerprints-v6.db
  udp-probes.db
  corpus-manifest.json

THIRD_PARTY_DATA.md
```

During delivery stages 1–2, the current `data/*.db` files remain authoritative until the canonical migration can round-trip them without behavioral regression. After that equivalence gate passes, the canonical corpus becomes the source of truth and `data/*.db` become generated runtime artifacts enforced by CI.

This avoids forcing a new runtime storage engine before corpus quality is proven.

A binary/indexed runtime format can be introduced later only if corpus scale demonstrates a measurable load-time or memory problem.

## 6. Canonical record model

All source adapters emit a shared canonical representation before compilation.

A fingerprint record contains, where applicable:

```text
id
kind
transport
address_family
probe_id
probe_payload_ref
matcher_type
matcher_expression
service
vendor
product
version
version_info
os_family
os_generation
device_type
cpe[]
ports[]
rarity
confidence
confidence_basis
evidence_requirements[]
negative_constraints[]
provenance[]
first_imported_revision
last_verified_revision
status
notes
```

Each `provenance[]` element contains:

```text
source_id
source_record_id
source_revision
source_url
source_license
source_hash
```

### Stable identifier

The canonical `id` is generated from normalized semantic fingerprint identity. It must not depend on source identity or import order.

Source-specific identity stays inside `provenance[]`. Equivalent records contributed by multiple sources can therefore merge under one canonical ID while retaining all source attribution.

A material semantic fingerprint change may produce a new canonical ID. Explicit aliases/overrides may preserve continuity where review determines that the record is still logically the same fingerprint.

### Source hash

Each provenance record stores a deterministic hash of the normalized upstream source material used to create that contribution. This allows change detection and reproducible audits.

### Revision metadata

`first_imported_revision` and `last_verified_revision` are reproducible source/build revision identifiers, not wall-clock timestamps. Human review timestamps may exist in pull-request metadata but do not affect generated corpus bytes.

### Status

Allowed statuses:
- `verified`
- `imported`
- `experimental`
- `suppressed`
- `deprecated`

Only statuses explicitly allowed by the compiler are emitted into production runtime artifacts.

## 7. Active probes vs passive matchers

The pipeline treats active probes and passive response fingerprints differently.

### Active probes

Active network payloads are high-risk from a correctness and operational perspective. In the first implementation:

- Skan first-party active probes remain the default active probe source;
- third-party active probe payloads are not imported automatically;
- a third-party source may contribute matcher intelligence without its active payload;
- new active probes require bounded payload size, explicit target protocol, test fixtures, and project review.

### Passive/response matchers

Permissively licensed response fingerprints can be normalized when their syntax and semantics can be represented safely.

Every matcher must pass pattern safety checks before compilation.

## 8. Pattern safety

Imported pattern languages must not be executed directly by Skan.

The normalizer converts accepted constructs into a restricted Skan matcher representation.

Validation rejects or quarantines:
- unsupported regex features;
- expressions with unacceptable worst-case complexity;
- unbounded captures;
- excessively large patterns;
- ambiguous all-purpose signatures;
- patterns that match empty input when not explicitly intended;
- patterns that produce conflicting metadata without a deterministic resolution rule.

Pattern evaluation remains bounded by existing service-detection response limits.

## 9. Normalization

Normalization has four independent responsibilities.

### Service normalization

Canonical service names come from Skan conventions plus authoritative registry aliases where useful.

Examples:
- normalize synonyms;
- retain original aliases separately;
- distinguish transport when the same name exists across TCP/UDP.

### Vendor/product normalization

Raw source names are mapped to canonical vendor/product identities.

The original source spelling is retained in provenance metadata or source staging material.

### Version normalization

Version output must preserve meaningful source evidence. The normalizer must not invent a version if only a product family is known.

### CPE normalization

CPE identifiers are enrichment metadata attached only when the detected vendor/product/version evidence supports that mapping.

A broad service match cannot be upgraded into a precise CPE solely because the CPE dictionary contains a similarly named product.

## 10. Deduplication

Deduplication works on semantic identity, not text equality alone.

Two records may be considered equivalent when they share:
- compatible matcher semantics;
- the same transport/probe context;
- equivalent normalized identity fields;
- compatible version extraction behavior.

When equivalent records come from multiple sources, the canonical record retains every provenance entry.

No source attribution is discarded during merge.

## 11. Conflict resolution

Conflict resolution is deterministic and evidence-first.

Default priority:

1. Skan verified first-party evidence
2. high-confidence permissive fingerprint with successful Skan fixtures
3. other imported fingerprint with explicit evidence
4. authoritative registry metadata
5. heuristic metadata

A lower-priority source cannot silently overwrite a higher-priority identification.

If two high-confidence fingerprints match the same evidence but disagree materially:
- the compiler marks the conflict;
- the conflicting entry is excluded from production unless an explicit override resolves it;
- the decision is recorded in `corpus/overrides/conflicts.json`.

## 12. Confidence model

Confidence is not based only on source reputation.

The score/band incorporates:
- matcher specificity;
- number of independent evidence fields;
- fixture quality;
- false-positive overlap;
- protocol context;
- version extraction precision;
- source verification state.

Recommended bands:
- `high`
- `medium`
- `low`

Runtime output should expose confidence only when the runtime evidence model can do so consistently. Corpus v2 can store it before UI/output exposure is added.

## 13. Source manifest

`corpus/sources/sources.json` is the source of truth for external data ingestion.

Each source entry contains:

```text
id
name
homepage
source_url
license_spdx_or_policy
redistribution_allowed
attribution_required
approved_data_classes[]
blocked_data_classes[]
pinned_revision
expected_hash
adapter
notes
```

CI fails if an importer references a source that is not present in this manifest.

A source with unknown or ambiguous redistribution terms is rejected by default.

For sources that do not expose an immutable revision identifier, the explicit update workflow materializes a snapshot under `corpus/snapshots/<source-id>/`, records its SHA-256 plus upstream cursor/modified metadata, and normal builds consume only that pinned snapshot.

## 14. Import pipeline

The pipeline is deterministic and staged:

```text
fetch/pinned input
  -> source adapter
  -> canonical staging records
  -> normalization
  -> schema validation
  -> pattern-safety validation
  -> deduplication
  -> conflict analysis
  -> fixture validation
  -> production eligibility filter
  -> runtime compiler
  -> manifest/statistics
```

Network fetching is not required during normal runtime, normal unit tests, or deterministic corpus builds.

CI normally consumes pinned snapshots. A separate explicit update workflow refreshes external source revisions/snapshots.

## 15. Reproducibility

Given the same:
- Skan source revision;
- source manifest;
- pinned upstream snapshots/revisions;
- overrides;
- compiler version;

the generated runtime databases and manifest must be byte-for-byte identical.

Generated artifacts include:
- compiler version;
- source revisions;
- aggregate source hashes;
- record counts by source/kind/status;
- rejected/suppressed counts.

Canonical/generated artifacts must not include the current wall clock. If a date is necessary, it must come from pinned upstream metadata or reproducible build metadata such as `SOURCE_DATE_EPOCH`. Human update/review time belongs in version-control/review metadata, not byte-for-byte runtime artifacts.

## 16. Runtime integration

Phase 1 of implementation keeps the current Skan runtime loaders.

After the stage-2 round-trip gate succeeds, the compiler produces the existing runtime formats:
- `data/service-probes.db`
- `data/os-fingerprints.db`
- `data/os-fingerprints-v6.db`
- `data/udp-probes.db`

This means corpus growth is decoupled from scanner-engine risk.

If the existing formats cannot represent a required canonical field, the compiler either:
- safely omits non-runtime enrichment while preserving it in canonical JSONL; or
- proposes a separately reviewed runtime schema change.

The corpus project must not quietly change existing runtime semantics.

## 17. Testing

### Adapter tests

Each importer has fixture-based tests that verify:
- source parsing;
- license/source identity tagging;
- stable IDs;
- malformed-record handling.

### Normalizer tests

Cover:
- aliases;
- vendor/product normalization;
- versions;
- CPE mappings;
- Unicode and escaping;
- deterministic ordering.

### Matcher tests

Every production matcher must have at least one of:
- a project-owned positive fixture;
- an upstream permissively licensed fixture that is allowed for redistribution;
- a deterministic generated protocol fixture where that is sufficient.

High-risk overlapping patterns require negative fixtures.

### Compiler tests

Verify:
- byte-for-byte determinism;
- no duplicate IDs;
- no unresolved production conflicts;
- no source without license metadata;
- stable sort order;
- current runtime loaders accept compiled artifacts.

### Runtime regression tests

Run the existing service/OS/UDP matcher tests against the compiled corpus and add a curated cross-protocol confusion suite.

Examples:
- HTTP vs generic text banners;
- SSH vs arbitrary `SSH-` prefix data;
- TLS vs random binary data;
- DNS vs malformed UDP payloads;
- vendor/product aliases that would otherwise collapse incorrectly.

## 18. CI gates

A corpus change cannot pass if any of the following occur:
- unapproved source;
- missing or ambiguous source license policy;
- source hash mismatch outside an explicit update workflow;
- duplicate stable IDs;
- unresolved high-confidence conflict;
- unsafe matcher;
- missing required fixture;
- generated runtime artifact drift after canonical corpus becomes authoritative;
- runtime loader failure;
- corpus statistics regress below configured quality thresholds without an explicit reviewed override.

CI emits a compact corpus report with:
- total records;
- production records;
- source distribution;
- service coverage;
- OS/device coverage;
- CPE coverage;
- conflicts;
- suppressed/rejected entries;
- fixture pass rate;
- compiler duration;
- runtime DB size.

## 19. Update workflow

External data updates are explicit, reviewable changes.

The update command/workflow:
1. fetches the configured upstream source;
2. records the new revision/hash or materialized snapshot hash;
3. imports and normalizes;
4. emits a source-diff report;
5. highlights added/removed/changed fingerprints;
6. reports license metadata changes;
7. rebuilds runtime artifacts when the canonical corpus is authoritative;
8. runs corpus and runtime validation.

It does not auto-merge.

Large upstream changes require a human-readable summary before approval.

## 20. Quality metrics

Record count is tracked but is not a primary success criterion.

Primary metrics:
- fixture precision;
- curated false-positive rate;
- percentage of production records with positive fixtures;
- percentage of overlapping patterns with negative fixtures;
- unresolved conflict count;
- provenance completeness;
- CPE precision for exact product/version evidence;
- load-time and memory impact;
- identification coverage on a controlled service fixture matrix.

Target invariants for production corpus:
- 100% records have source/provenance metadata;
- 100% external records have an approved source policy;
- 0 unresolved high-confidence conflicts;
- 0 known unsafe matcher patterns;
- 100% generated artifacts reproducible from pinned inputs;
- all existing Skan runtime corpus tests remain green.

## 21. Performance design

The compiler may process large source datasets, but runtime must remain bounded.

Initial performance strategy:
- compile offline, not at scan time;
- pre-normalize metadata;
- sort/group matchers by transport/probe/service context;
- preserve existing bounded response sizes;
- avoid loading unused source/provenance metadata into hot runtime matcher structures when not required.

Only after measurement shows a bottleneck should Skan introduce:
- compact binary indexes;
- memory mapping;
- prefix automata;
- regex preclassification;
- lazy metadata tables.

## 22. Security and trust boundaries

The corpus pipeline consumes untrusted external text/data.

Therefore:
- parsers use strict size limits;
- decompression has explicit maximum expanded size;
- no imported source executes code;
- no importer evaluates upstream expressions with `eval` or a shell;
- regex/pattern syntax is parsed and normalized, not blindly executed;
- network update steps are separate from deterministic build/test steps;
- source URLs and hashes are pinned;
- generated files are treated as build outputs, not executable content.

## 23. Attribution and auditability

`THIRD_PARTY_DATA.md` is generated or validated from the active source manifest and lists the third-party datasets shipped with Skan, their licenses, source revisions, and required attribution. Packaging must include equivalent attribution whenever external corpus data is distributed in a Skan package.

`data/corpus-manifest.json` records sufficient metadata to answer:
- which sources contributed to this release;
- which upstream revisions/snapshots were used;
- how many contributions came from each source;
- which licenses/attributions apply;
- which compiler version produced the runtime artifacts.

No user scan output needs to disclose third-party source provenance per fingerprint unless a source license requires it; repository/package attribution is the default location.

## 24. Nmap comparison policy

Nmap is an important benchmark, but it is not an import source under the default policy.

Comparison tests may measure:
- service detection agreement;
- OS-family/device-type agreement;
- detection latency;
- false positives;
- unknown-rate differences.

A Skan result should be considered better only when a controlled benchmark demonstrates better measurable behavior, not because the Skan database contains more rows or bytes.

## 25. Delivery sequence

Implementation is split into separate reviewable stages/PRs rather than one giant corpus change:

1. Corpus schema, source manifest, validator, deterministic compiler skeleton.
2. Migrate current Skan first-party corpus into the canonical model and prove round-trip behavior before switching the source of truth.
3. Add IANA normalization adapter.
4. Add Rapid7 Recog adapter for approved passive fingerprint classes.
5. Add current NVD/CPE normalization/enrichment adapter.
6. Add dedupe/conflict engine and explicit override files.
7. Expand fixtures and cross-protocol false-positive suite.
8. Add source-update workflow and generated attribution/corpus statistics.
9. Measure runtime scale and decide whether the existing text runtime DB format remains sufficient.
10. Run controlled coverage/accuracy comparison against Nmap and other relevant scanners without importing their restricted data.

Each stage must be independently testable and must not require the next stage to preserve existing scanner functionality.

## 26. Acceptance criteria

Fingerprint Corpus v2 is considered architecturally complete when:
- all external data sources are declared and auditable;
- the canonical schema can represent current Skan service/OS/UDP records;
- the current corpus can round-trip through the compiler without behavioral regression;
- at least one authoritative registry adapter and one permissively licensed fingerprint adapter are implemented;
- CPE normalization is evidence-gated;
- unsafe/unsupported matcher constructs are quarantined rather than silently accepted;
- duplicate/conflicting records are surfaced deterministically;
- runtime artifacts are reproducible;
- package/repository attribution is complete;
- the scanner can consume the generated databases through its normal loaders;
- corpus quality is reported with precision-oriented metrics, not only size/count.

## 27. Source-policy references

The implementation re-verifies source terms at adapter introduction/update time rather than relying forever on this design note.

Current design references:
- Nmap Public Source License / legal guidance: `https://nmap.org/npsl/` and `https://nmap.org/book/man-legal.html`
- IANA licensing terms for protocol registries: `https://www.iana.org/help/licensing-terms`
- Rapid7 Recog repository/license: `https://github.com/rapid7/recog`
- NIST/NVD public data and current CPE resources: `https://nvd.nist.gov/`

License compatibility decisions in code review are engineering/distribution safeguards, not legal advice. If source terms are ambiguous, the source stays disabled until clarified.
