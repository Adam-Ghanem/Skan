# Intelligence Database v2

Skan Intelligence Database v2 uses two fail-closed, offline corpus authorities:

- `corpus/canonical/` is the governed mirror of the first-party databases that
  compile deterministically to the packaged `data/*.db` runtime authority.
- `corpus/external/` is generated public-source intelligence bound by a separate
  manifest. It is governed input for future runtime work, not active scanner
  detection data.

This milestone changes corpus storage and verification only. In particular,
`skan -sV` does not load records from `corpus/external/`.

## Source governance

`corpus/sources/sources.json` governs the clean-room first-party mirror.
`corpus/sources/external-sources.json` governs generated public-source records.
The standard-library validators reject unknown fields, unsafe identifiers,
incorrectly bound revisions, unapproved licenses, non-redistributable data,
missing attribution, malformed hashes, and untrusted identities. Validation is
offline and never executes adapters.

Each represented external source must have a lock under `corpus/locks/`. The
lock binds the source revision, download URL, license policy, and content hash
to record provenance. `corpus/THIRD_PARTY_NOTICES.md` is regenerated from those
represented sources and compared byte-for-byte during verification.

Nmap is comparator-only. Its code and fingerprint databases are not imported,
derived, translated, or accepted as corpus source material.

## Canonical schema

Every canonical record uses schema version 2, a full SHA-256 semantic ID, strict
provenance, and one immutable typed body:

- active service probe;
- service matcher;
- OS fingerprint with typed signatures; or
- UDP probe.

IDs include all runtime-relevant fields. Governance metadata does not change a
record's identity. Equivalent literal text and hexadecimal byte matchers share
one identity; non-semantic port and OS-signature ordering is canonicalized.

The model enforces selected C++ loader-compatible domains and conservative
bounds, including exact OS operators, TCP-option aliases, runtime behavior
values, optional probe timeouts, bounded payloads, NFC text, safe line-format
tokens, and immutable source revisions. Complete regex compilation and
runtime-loader validation remain part of the later real-loader migration gate.

## Deterministic storage

Canonical JSONL is UTF-8, LF-terminated, key-sorted, compact, bounded by file,
line, and record limits, and ordered deterministically by kind and ID. Loading
rejects duplicate JSON keys and record IDs, malformed UTF-8, non-standard JSON
constants, oversized integers, surrogate code points, and incompatible kinds.

Writes revalidate every record against source policy, stage in the destination
directory, flush and synchronize the temporary file, and replace the target
atomically. A failed validation or replacement preserves the previous file and
cleans temporary state.

Run the contract suite with:

```bash
make test-corpus
```

## First-party runtime mirror and loader gate

The populated files in `corpus/canonical/` are the governed, verified canonical
mirror of Skan's four first-party runtime databases. Its commit-marker manifest
binds these stores by kind, count, and hash:

- `active-probes.jsonl`;
- `services.jsonl`;
- `os.jsonl`; and
- `udp.jsonl`.

Readers reject incomplete or mixed generations. The empty
`corpus/canonical/products.jsonl` file is a backward-compatible enrichment
placeholder. It is not manifest-bound and is not a runtime database.

The canonical stores compile deterministically to `service-probes.db`,
`udp-probes.db`, `os-fingerprints.db`, and `os-fingerprints-v6.db`. The reviewed
copies under `data/` remain the production and package runtime authority.
`build/corpus-runtime/` is generated and ignored.

The offline lifecycle is:

```bash
python3 -m tools.corpus.cli import-runtime
python3 -m tools.corpus.cli compile --output-dir build/corpus-runtime
python3 -m tools.corpus.cli verify-roundtrip --output-dir build/corpus-runtime
make test-corpus-runtime
```

Re-import preserves `first_imported_revision` for every unchanged semantic ID
while advancing current provenance and `last_verified_revision`. During a
source-pin migration, a prior complete generation can be supplied with
`import-runtime --history-dir <repository-relative-directory>`; its manifest,
store hashes, counts, schema, and semantic IDs are validated before history is
reconciled. New semantic IDs always receive the current pinned revision. A
damaged canonical generation is rejected by default; the explicit
`--discard-history` recovery option rebuilds it without preserving import
history and cannot be combined with `--history-dir`.

`verify-roundtrip` compares source runtime semantics, canonical records, and
deterministically compiled artifacts. `make test-corpus-runtime` then loads all
four generated databases through the production C++ `load_file` APIs and checks
coverage counts plus representative typed semantics. The command performs no
network access, scanning, adapter execution, or shell execution from corpus
tooling.

The source-policy rules above remain mandatory for all corpus changes: preserve
the pinned first-party source identity and license terms, and do not copy,
derive, or import Nmap or proprietary fingerprint data.

## Generated external intelligence

`corpus/external/` contains a complete generated public-source generation. Its
own `manifest.json` binds the exact SHA-256, record count, and per-kind counts
for every expected JSONL store, including intentionally empty stores. The
current committed generation contains:

- 30,535 total records;
- 17,824 detection records;
- 2,302 passive service matchers;
- 15,522 web fingerprints; and
- 12,711 port-registry records.

These counts describe governed committed intelligence, not current `-sV`
coverage. External service and web records are not loaded by the scanner. Port
registry assignments are metadata and are not product-detection evidence.

The external verifier checks the exact store inventory, manifest hashes and
counts, canonical records, duplicate identities, unresolved conflicts,
provenance against source locks, corrected post-deduplication statistics, and
third-party notices. Run the complete offline boundary check with:

```bash
make -f GNUmakefile corpus-external-verify
```

`tools.corpus.bulk_refresh` stages a complete generation under an isolated
output root. Refresh publication is deterministic: two generations from the
same pinned inputs must be byte-identical, and only the generated external
directory, locks, corrected statistics, and notices are installed. It never
publishes external records into `corpus/canonical/`.

## Next runtime milestone

Activating passive external service intelligence requires a separately bounded
runtime index. That milestone must preserve protocol evidence, include collision
negative fixtures, enforce measured memory and lookup-latency limits, and reject
port-only product guessing. Until those acceptance criteria are met, external
records remain verified offline intelligence rather than scanner runtime rules.
