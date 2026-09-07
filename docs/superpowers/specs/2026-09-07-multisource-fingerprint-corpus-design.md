# Skan Multi-Source Fingerprint Corpus Design

**Status:** Design approved in chat; written specification pending maintainer review.

## 1. Purpose

Skan currently has a small first-party detection corpus and a verified lossless corpus pipeline. This design expands that foundation into a large, maintainable, multi-source fingerprint and product-intelligence corpus without copying Nmap's licensed databases into Skan.

The objective is not to maximize file size. The objective is to maximize useful detection coverage while preserving precision, provenance, licensing clarity, deterministic builds, and reproducible benchmarking.

The target end state is:

1. tens of thousands of useful service, device, and web-technology detection rules when validated source coverage supports that scale;
2. the complete IANA service/port registry as authoritative protocol metadata;
3. a full normalized CPE/product intelligence layer sourced from current NVD CPE data;
4. first-party active probes and OS/device fingerprints grown through clean-room lab evidence;
5. measurable service/product detection quality that can be compared directly with Nmap on a truth-labelled private benchmark suite.

CPE/product metadata counts are reported separately from detection fingerprint counts. Millions of product identifiers must never be presented as millions of detection fingerprints.

## 2. Non-goals

This project will not:

- copy, mechanically translate, reformat, or commit `nmap-service-probes`, `nmap-os-db`, or other Nmap NPSL-covered databases into Skan;
- claim byte-for-byte or schema compatibility with Nmap databases;
- silently resolve conflicting fingerprints by source popularity;
- accept weak single-token fingerprints merely to increase record count;
- require network access during normal Skan builds, tests, package builds, or runtime scans;
- make NVD vulnerability data a prerequisite for basic service detection;
- replace Skan's first-party runtime scanner with Nmap, Nerva, ZGrab2, or another scanner.

## 3. Source policy

Every imported source must have a source manifest entry with a pinned revision or release identifier, expected content hash where applicable, license/policy identifier, redistribution flag, attribution requirements, approved data classes, and adapter name.

The corpus validator remains fail-closed: an unknown source, disallowed data class, missing required attribution metadata, invalid hash, or redistribution policy violation fails verification.

### 3.1 Tier 0: Skan first-party

**Source:** Skan-owned fingerprints, probes, fixtures, and lab captures.

**Priority:** Highest.

**Allowed classes:** `service_matcher`, `active_probe`, `udp_probe`, `os_fingerprint`, `web_fingerprint`, `product_alias`, and future first-party device fingerprints.

First-party entries must retain the strongest trust level because they can be validated against controlled positive and negative fixtures and can be changed without third-party licensing constraints.

### 3.2 Tier 1: Redistributable detection datasets

#### Rapid7 Recog

- License policy: BSD-2-Clause with attribution retained.
- Role: service, protocol, hardware, operating-system, and product banner fingerprints.
- Intended imported classes: primarily `service_matcher`, `device_fingerprint`, and product identity metadata where the source record actually provides them.
- Import rule: preserve upstream matcher semantics exactly enough to reproduce detection behavior; unsupported matcher constructs are rejected or reported, never approximated silently.

#### ProjectDiscovery WappalyzerGo

- License policy: MIT with required copyright/license notice retained.
- Role: HTTP/web technology identification.
- Intended imported class: `web_fingerprint` plus normalized product aliases.
- Import rule: HTTP header, cookie, HTML, script, and other web match dimensions stay distinct in canonical form so confidence can reflect evidence strength.

### 3.3 Tier 1: Authoritative metadata datasets

#### IANA Protocol Registries

- Policy: protocol registry data is treated under the IANA/IETF CC0 dedication.
- Role: authoritative service names, ports, transports, protocol registry metadata, and aliases.
- Intended imported classes: `port_registry` and `product_alias` only when semantically appropriate.
- IANA assignments are metadata, not proof that a live service is actually the registered service for a port. Port number alone must not produce a high-confidence product detection.

#### NVD CPE Dictionary

- Role: normalize vendor, product, version, edition, target platform, and CPE identity.
- Intended imported class: `product_record` / `cpe_record` enrichment, not a service matcher.
- CPE data is a product intelligence layer and does not create detection evidence by itself.
- The importer must support the current NVD 2.0 CPE data model rather than retired legacy feeds.

### 3.4 Tier 2: Permissive protocol implementation references

#### Nerva

- License policy: Apache-2.0 obligations retained for any reused covered material.
- Role: reference for active protocol negotiation and validation coverage.
- Default policy: do not bulk-convert implementation code into fingerprints. Prefer protocol standards and Skan-owned clean-room probes. If a machine-readable upstream probe definition is imported, it must enter through a dedicated adapter with provenance and license attribution.

#### ZGrab2

- License policy: Apache-2.0/ISC obligations retained as applicable to the exact imported material.
- Role: reference for protocol-aware active handshakes and response parsing.
- Default policy: same as Nerva. The preferred outcome is independent Skan probes derived from public protocol specifications and validated in Skan's lab.

### 3.5 Nmap reference policy

Nmap is a benchmark and optional local reference provider, not a committed corpus source.

Skan may:

- execute a user/developer-installed Nmap in isolated benchmark jobs;
- parse Nmap scan output for comparison;
- inspect coverage gaps at a high level;
- expose a developer-only local comparator that reports what Nmap identified for the same truth-labelled target.

Skan must not:

- import Nmap database entries into committed canonical JSONL;
- emit generated runtime fingerprints derived from Nmap database rows;
- use Nmap fingerprints as provenance for Skan-owned fingerprints;
- mechanically transform Nmap regexes, probes, OS signatures, or match tables.

When Nmap identifies something Skan misses, that result creates a gap ticket or benchmark observation. The replacement Skan fingerprint must be independently authored from protocol documentation, vendor documentation, first-party captures, or another redistribution-approved source.

## 4. Canonical data model extensions

The existing canonical model remains the source of truth. It is extended only where a new source requires a semantically distinct field.

Required logical classes are:

- `active_probe`
- `service_matcher`
- `udp_probe`
- `os_fingerprint`
- `web_fingerprint`
- `device_fingerprint`
- `port_registry`
- `product_record`
- `product_alias`
- `cpe_record`

All detection records require:

- stable semantic ID;
- ordered provenance list;
- matcher/evidence type;
- normalized identity output;
- source-specific confidence input or evidence quality label;
- positive fixture reference where practical;
- negative fixture reference for rules with realistic collision risk;
- optional deprecation/suppression status.

Product metadata records are explicitly separated from detection records. A `product_record` or `cpe_record` cannot directly mark a target as detected.

## 5. Import and normalization pipeline

The pipeline is deterministic and split into independently testable stages:

```text
source lock
  -> fetch/verify snapshot
  -> source adapter
  -> canonical validation
  -> normalization
  -> semantic deduplication
  -> conflict detection
  -> fixture validation
  -> confidence calibration
  -> compiled runtime data
  -> benchmark/reporting
```

### 5.1 Source locks

A source lock records:

- source ID;
- upstream revision/release;
- source URL;
- content hash;
- license/policy identifier;
- adapter version.

Normal CI never performs an unpinned network fetch. Refreshing a source is an explicit operation that updates the lock and produces a reviewable corpus diff.

### 5.2 Adapters

Each source has one focused adapter. Adapters do not perform cross-source conflict resolution.

Initial adapters:

- `recog`
- `wappalyzergo`
- `iana_services`
- `nvd_cpe`

Later protocol-reference adapters, if justified by machine-readable data and license review:

- `nerva_reference`
- `zgrab2_reference`

The Nmap comparator is not an import adapter and never returns canonical records.

### 5.3 Normalization

Normalization must be deterministic and conservative:

- lowercase only fields whose semantics are case-insensitive;
- normalize transport names and port ranges;
- normalize vendor/product aliases through explicit alias tables;
- preserve raw upstream identity text in provenance metadata when useful for audit;
- normalize CPE 2.3 fields without guessing missing version or edition data;
- preserve matcher ordering when source semantics depend on order.

### 5.4 Deduplication

Two records deduplicate only when their semantic matcher and normalized result identity are equivalent under the canonical model.

When duplicate records come from multiple sources, provenance is merged. Source count does not automatically raise confidence.

### 5.5 Conflicts

A conflict is emitted when overlapping matcher conditions can identify the same evidence as incompatible products, versions, device types, or operating systems.

Conflicts are resolved only by:

1. making conditions disjoint;
2. adding stronger evidence;
3. suppressing a known-bad rule with a documented reason; or
4. adding an explicit reviewed conflict resolution entry.

No source wins merely because it has higher priority.

## 6. Confidence model

Confidence is evidence-driven, not source-count-driven.

The first implementation uses discrete evidence quality bands rather than pretending to have statistically calibrated probabilities:

- `verified`: independently reproduced in Skan fixtures/lab and uniquely identifies the result;
- `strong`: multiple independent response features or a highly specific protocol/banner pattern identify the result;
- `medium`: a useful but potentially shared signature that requires supporting context;
- `weak`: heuristic evidence that may contribute to a result but cannot produce a high-confidence identity alone.

A final detection may combine compatible evidence from active probe response, banner, TLS, HTTP, web fingerprint, device hint, and OS fingerprint. Contradictory evidence lowers confidence or yields an explicit ambiguity instead of arbitrary selection.

Port registry metadata is `weak` evidence for identity by itself.

CPE metadata is enrichment only and contributes zero detection confidence unless a separate detector has already identified the corresponding product/version.

## 7. Storage and compilation

### 7.1 Git-tracked canonical corpus

Redistribution-approved normalized detection records are stored in deterministic JSONL under `corpus/canonical/`.

Large third-party raw snapshots are not committed merely to duplicate upstream archives. Their pins and hashes are committed; refresh tooling obtains them explicitly and verifies the lock.

### 7.2 Runtime output

During the first expansion phases, the compiler continues emitting the runtime formats already consumed by Skan so scanner changes are not coupled to source-import work.

When compiled detection data becomes large enough to create measurable startup or memory regressions, a separate indexed/sharded runtime format may be proposed. That change requires its own design and benchmark evidence; it is not silently introduced as part of source ingestion.

### 7.3 Full product/CPE intelligence

Full CPE/product intelligence may become much larger than the detection corpus. It must be packaged and measured separately so the core scanner can remain lightweight.

The preferred packaging split is:

- core Skan detection data required for normal scanning;
- optional/full product intelligence artifact when the complete CPE knowledge base materially increases package size.

The exact split is decided from measured artifact size and lookup performance, not an arbitrary threshold.

## 8. Update workflow

Source refresh is explicit and reviewable:

1. request refresh for one source;
2. fetch the pinned upstream revision/release;
3. verify license/policy metadata and content hash;
4. run that adapter;
5. print added/removed/changed record counts;
6. run dedupe and conflict analysis;
7. run fixture and corpus validation;
8. run first-party runtime round-trip verification;
9. run benchmark delta where the source affects detection;
10. commit lock + normalized corpus changes together.

A refresh fails if it introduces unresolved conflicts, malformed entries, unsupported semantics, missing attribution, unapproved data classes, or a material precision regression.

## 9. Testing strategy

### 9.1 Adapter unit tests

Every adapter requires fixtures covering:

- valid representative source entries;
- unsupported source constructs;
- malformed input;
- identity normalization;
- matcher escaping;
- deterministic record IDs;
- provenance and attribution fields.

### 9.2 Corpus invariants

`make corpus-verify` continues to be network-free and must verify:

- source policy;
- canonical schema;
- global ID uniqueness;
- deduplication semantics;
- explicit unresolved conflicts;
- snapshot hashes for locally available pinned fixtures;
- deterministic JSONL;
- first-party runtime parse/emit/parse round-trip;
- packaging dependency guards.

### 9.3 Positive and negative detection fixtures

High-impact or collision-prone rules require both positive and negative fixtures. Broad web tokens, generic server strings, and shared vendor banners cannot be promoted to `strong` or `verified` without negative evidence.

### 9.4 Fuzzing

Adapters and compiled database parsers receive fuzz targets or malformed corpus suites once they process untrusted external text at scale.

## 10. Nmap benchmark and quality gates

A private, isolated, truth-labelled lab is the authoritative comparison environment.

For each target/service instance, ground truth includes at least:

- protocol;
- product;
- version when intentionally exposed;
- device class where relevant;
- OS family/version where relevant.

Both Skan and Nmap scan the same target with comparable discovery/service/version options.

Report separately:

- service protocol accuracy;
- product top-1 precision;
- product recall/coverage;
- exact version accuracy;
- device-class accuracy;
- OS-family and OS-version accuracy;
- false-positive rate;
- ambiguous-result rate;
- scan overhead attributable to detection;
- corpus load/startup time;
- peak memory attributable to detection data.

Skan may claim better service/product identification than the benchmarked Nmap version only when, on the published internal benchmark definition:

1. Skan product precision is at least Nmap's;
2. Skan product recall is greater than Nmap's for the supported benchmark set;
3. Skan false-positive rate is no worse than Nmap's; and
4. the exact benchmark target set, versions, and commands are recorded with the result.

OS detection remains a separate claim until Skan's OS benchmark independently satisfies equivalent quality gates.

## 11. Scale goals and reporting

Scale is tracked, but quality gates outrank count.

The program aims for:

- an order-of-magnitude increase in validated detection records during the first external-source phases;
- a long-term corpus on the order of 10,000+ useful detection rules if imported sources and validation support that quantity;
- complete current IANA registry coverage in the metadata layer;
- complete supported current NVD CPE snapshot coverage in the product-intelligence layer.

Every corpus stats report separates:

- active probes;
- service matchers;
- web fingerprints;
- device fingerprints;
- OS fingerprints;
- UDP probes;
- port-registry records;
- product records;
- CPE records;
- aliases;
- suppressed records;
- unresolved conflicts.

No aggregate “database size” number may mix detection fingerprints with product metadata without also showing this breakdown.

## 12. Phased rollout

### Phase A: Recog + IANA

Deliverables:

- source manifests/locks;
- Recog adapter;
- IANA service/port adapter;
- source attribution output;
- canonical import/dedupe/conflict tests;
- corpus statistics delta;
- no runtime scanner code changes unless a canonical field required for lossless semantics is missing.

This phase produces the first large service/device corpus expansion.

### Phase B: WappalyzerGo + product aliases

Deliverables:

- dedicated `web_fingerprint` canonical class;
- WappalyzerGo adapter;
- HTTP evidence-dimension preservation;
- broad-pattern negative fixtures;
- compiled web-detection data only after correctness tests exist.

### Phase C: NVD CPE enrichment

Deliverables:

- current NVD 2.0 CPE ingest;
- normalized product/CPE store;
- vendor/product alias linking;
- lookup from a detected normalized product/version to CPE candidates;
- ambiguity-preserving lookup when multiple CPEs remain valid;
- package-size and lookup-performance report.

### Phase D: Active protocol breadth

Deliverables:

- gap analysis from the private benchmark;
- independently authored first-party probes for high-value missing protocols;
- protocol-reference review against standards, Nerva, and ZGrab2 where useful;
- lab fixtures and negative tests for each new probe family.

### Phase E: OS/device corpus expansion

Deliverables:

- first-party clean-room OS/device fingerprints generated from controlled lab targets and documented public behavior;
- broader IPv4/IPv6 coverage;
- independent Nmap comparison without copying Nmap OS signatures;
- dedicated OS quality gate before any “better than Nmap OS detection” claim.

## 13. Security and privacy

The refresh/import pipeline processes public source datasets only.

First-party capture contribution tooling, if added later, must default to local/private processing and strip or explicitly exclude secrets, credentials, payload bodies unrelated to fingerprinting, user identifiers, and private network identifiers before any contribution is proposed.

No telemetry or automatic fingerprint upload is part of this design.

## 14. Acceptance criteria

This multi-source design is ready for implementation when:

1. the source policy is encoded in `corpus/sources/sources.json` and/or a lock companion without weakening the current fail-closed validator;
2. Recog and IANA are implemented first and can be refreshed deterministically from pinned source revisions;
3. imported records preserve provenance and required attribution;
4. Nmap data cannot enter committed canonical records through the import path;
5. product/CPE metadata is structurally separated from detection evidence;
6. unresolved matcher conflicts fail verification;
7. `make corpus-verify` remains network-free;
8. Debian/Ubuntu package validation remains green;
9. benchmark tooling reports Skan vs Nmap from the same truth-labelled isolated targets;
10. no “better than Nmap” claim is emitted unless the benchmark gates in Section 10 are satisfied.

## 15. Recommended implementation order

Implement this as separate reviewable stacks rather than one giant PR:

1. **Recog + IANA source infrastructure and adapters**
2. **WappalyzerGo web fingerprint model and adapter**
3. **NVD CPE product intelligence**
4. **active protocol breadth from measured gaps**
5. **OS/device clean-room expansion**

Each stack must leave the corpus pipeline valid, deterministic, packageable, and independently reviewable before the next source is added.
