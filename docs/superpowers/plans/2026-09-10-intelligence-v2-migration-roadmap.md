# Intelligence Database v2 Migration Roadmap

**Mission:** Make canonical Intelligence Database v2 the production-authoritative source without changing runtime semantics until equivalence is proven through the real C++ loaders.

## Engineering decision gate

For every change, ask whether it moves Skan closer to accurate, explainable, production-authoritative network intelligence without unnecessary technical debt, hidden complexity, or unproven behavior.

## Current increment — UDP vertical slice

Status: implementation proposed in PR #33; runtime authority remains `data/udp-probes.db` until verification and merge.

Acceptance criteria:

- Parse the pinned first-party UDP runtime corpus with bounds no weaker than its runtime semantic limits.
- Normalize only semantics-preserving representation details such as hexadecimal case.
- Produce schema-v2 records with deterministic semantic IDs and pinned provenance.
- Reject malformed rows, duplicate probe names, duplicate non-zero ports, invalid DEFAULT semantics, oversized payloads, and invalid response bounds.
- Atomically write canonical JSONL and generated runtime text.
- Reload canonical JSONL and prove stable semantic IDs.
- Recompile runtime text deterministically.
- Load both legacy and generated runtime DBs through the production `UDPProbeDatabase` C++ implementation and compare ordered definitions, default selection, port lookup, payloads, hints, and response bounds.
- Do not switch packaging or runtime authority in this increment.

## Next implementation order

### 1. Active service probes

Port only the existing `Probe` and `send` runtime grammar into canonical `active_probe` records. Preserve declaration order, transport, payload bytes, rarity, priority, timeout, port hints, and fallback names. Reject unresolved fallbacks before compilation. Prove generated probes through the production C++ service loader.

### 2. Service matchers

Port hard/soft match rules with exact runtime matcher semantics, bounded regex policy, capture templates, evidence-bearing metadata, confidence, and rule order. Preserve binary matcher bytes losslessly. Add conflict keys that prevent ambiguous duplicate rules without incorrectly collapsing semantically distinct ordered rules.

### 3. Service corpus cross-record validation

Validate probe-name uniqueness, fallback references, rule ownership, declaration/rule ordering, matcher bounds, and generated-runtime equivalence as one corpus graph. Produce a deterministic semantic manifest before changing authority.

### 4. OS IPv4 and IPv6

Port both OS runtime databases. First correct kind-specific conflict keys so IPv4 and IPv6 identities cannot be incorrectly conflated. Preserve stable runtime IDs, typed signatures, specificity, family, class metadata, and ordering semantics. Prove both generated files through the production OS loaders.

### 5. Corpus-wide semantic manifest

Generate a versioned manifest containing corpus schema version, source revisions, artifact hashes, semantic record counts, kind counts, and deterministic semantic digests. The manifest must distinguish byte-level artifact identity from semantic identity.

### 6. Production authority gate

Only after all four corpus kinds pass migration, cross-record validation, generated-runtime compilation, and real-loader equivalence:

- make canonical v2 the source of truth;
- generate runtime DBs during the controlled build/release path;
- verify artifact hashes and semantic manifest before packaging;
- keep atomic update and rollback behavior;
- add startup and resident-memory benchmarks;
- retain a documented rollback path to the previous known-good corpus version.

## Explicit non-goals during migration

- No new scanner engine.
- No duplicated production parser.
- No fingerprint coverage expansion mixed into migration-equivalence work.
- No vulnerability matching until product/version identity is trustworthy.
- No performance claims without benchmark evidence.
- No generated corpus becomes authoritative merely because it compiles.
