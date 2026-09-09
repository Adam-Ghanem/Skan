# Intelligence Database v2 Foundation Design

## Outcome

Establish a governed, versioned, deterministic source-corpus layer without changing the scanner's runtime databases or identification behavior. The existing first-party files under `data/` remain authoritative until a later compiler increment proves byte-stable canonical round trips through the real C++ loaders.

## Trust boundaries

- Corpus input is untrusted structured data and is parsed fail-closed.
- Source identifiers cannot contain path syntax.
- Unknown manifest or record fields are rejected.
- Redistribution, data-class authorization, pinned revisions, attribution, and hashes are policy, not descriptive metadata.
- No tooling downloads data or executes adapters dynamically.
- No Nmap or proprietary corpus content is accepted.

## Initial architecture

`corpus/sources/sources.json` defines approved sources. `tools/corpus/sources.py` validates that manifest into immutable policies. `tools/corpus/model.py` owns schema-v2 records, provenance, stable semantic identifiers, bounds, and kind-specific validation. `tools/corpus/io.py` owns bounded deterministic JSONL encoding and decoding. Tests use synthetic records only.

The source layout is introduced under `corpus/` because it is build input, while compiled runtime artifacts remain under `data/`. A later compiler will make this lifecycle explicit:

`runtime v1 data -> canonical v2 -> validate -> compile -> C++ loader contract -> checksums`.

## Decisions

- Python standard library only for build-time corpus tooling.
- Canonical schema version is explicit on every record.
- Stable IDs include all runtime-semantic fields and exclude governance annotations.
- JSONL parsing is bounded by file, line, record, string, and collection limits.
- Unicode text must already be NFC-normalized; silent normalization is rejected.
- Writes are staged and atomically replaced only for individual files in this increment.
- Empty canonical stores are permitted only as migration staging and are never described as a production corpus.

## Deferred from this increment

- Migrating the current runtime corpus.
- Switching runtime loading to compiled v2 artifacts.
- Conflict overrides, negative evidence, fixtures, indexes, calibration, and release manifests.
- External source ingestion.

## Acceptance

- Strict source-policy tests reject traversal IDs, unknown fields, class overlap, missing pins, and missing attribution.
- Strict record tests reject empty or mismatched IDs, unknown fields, incompatible schema versions, invalid provenance bindings, and out-of-bounds data.
- Deterministic JSONL round trips are byte-stable and reject oversized or non-normalized input.
- Existing C++ behavior and data files are unchanged.
