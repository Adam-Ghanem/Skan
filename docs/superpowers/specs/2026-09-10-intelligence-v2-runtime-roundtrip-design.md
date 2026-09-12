# Intelligence Database v2 Runtime Round-Trip Design

## Outcome

Migrate Skan's first-party runtime databases into the governed canonical v2
corpus and prove that the canonical records can deterministically regenerate
artifacts accepted by the existing C++ loaders. Runtime scanning continues to
ship the reviewed files under `data/` until this migration gate is green.

## Selected approach

The compiler targets Skan's existing, project-owned text formats. Introducing a
second runtime format would duplicate parser security work and add no operator
value. Directly editing runtime files would leave provenance and reproducibility
unresolved. A clean-room importer plus deterministic compiler gives Skan one
governed source of truth while preserving the tested C++ runtime boundary.

## Components

- `tools/corpus/runtime.py` parses the four bounded Skan runtime files into
  canonical records. It implements Skan's grammar directly and performs no
  downloads, dynamic imports, or command execution.
- `tools/corpus/compiler.py` validates cross-record references and compiles a
  complete canonical set into service, UDP, IPv4 OS, and IPv6 OS artifacts.
- `tools/corpus/cli.py` exposes explicit offline `import-runtime`, `compile`, and
  `verify-roundtrip` commands with typed failures and non-zero exit status.
- `tests/integration/corpus/test_compiled_runtime.cpp` loads compiler output via
  the real `ServiceProbeDatabase`, `UDPProbeDatabase`, and
  `OSFingerprintDatabase` implementations.
- A semantic manifest records canonical IDs, record counts, and SHA-256 artifact
  hashes. It is written last so incomplete output cannot be mistaken for a
  verified corpus.

## Data flow

```text
reviewed data/*.db
  -> bounded runtime parser
  -> canonical v2 records with pinned first-party provenance
  -> deterministic JSONL
  -> cross-record validation
  -> deterministic compiler
  -> generated runtime artifacts
  -> bounded runtime parser (semantic equality)
  -> real C++ loaders (acceptance and representative semantics)
```

Comments and formatting in the legacy files are not runtime semantics and are
not round-tripped. Payload bytes, matcher bytes, regex bytes, rule order, probe
order, ports, fallbacks, OS signatures, and address family are semantics and
must round-trip exactly. Regex patterns containing control bytes use
`pattern_hex`; textual regexes continue to use `pattern`.

## Trust boundaries and failure behavior

- Runtime input, canonical JSONL, and output paths are untrusted.
- Existing file, line, record, payload, regex, signature, and collection bounds
  remain equal to or stricter than the C++ loaders.
- Unknown directives, duplicate fields, duplicate names, unresolved matcher or
  fallback references, cross-transport fallbacks, duplicate UDP ports, missing
  default UDP probe, invalid status, and mixed OS families fail closed.
- Only `verified` records compile in this increment. Other lifecycle states are
  rejected rather than silently omitted.
- Compilation validates the complete corpus in memory before writing. Files are
  staged in the destination directory and atomically replaced; the manifest is
  published last.
- No Nmap or proprietary code, formats, or data are imported. The only source is
  the pinned Skan first-party corpus authorized by `corpus/sources/sources.json`.

## Runtime compatibility gate

The generated service artifact must preserve probe and matcher order because
the scheduler and matcher use declaration order. OS signature order is
canonicalized by field because the matcher is field-based. UDP entries preserve
declaration order and retain exactly one port-zero default probe.

The migration is accepted only when:

1. importing the reviewed runtime files produces valid non-empty canonical
   stores for all four record kinds;
2. reloading those stores is byte-stable;
3. compiling twice produces byte-identical artifacts and manifest;
4. re-importing compiled artifacts produces the same semantic record IDs;
5. the real C++ loaders accept every artifact and expose representative records;
6. the existing scanner test suite remains green.

## Deferred

- Switching packaged runtime resources from reviewed `data/` files to generated
  artifacts.
- External source adapters or automatic downloads.
- Corpus conflict overrides, negative evidence, calibration, and signing.
- Increasing fingerprint coverage; this increment establishes the trustworthy
  build path required before adding records at scale.
