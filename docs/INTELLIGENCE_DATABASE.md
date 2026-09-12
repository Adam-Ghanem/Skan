# Intelligence Database v2

Skan Intelligence Database v2 starts with a fail-closed build-time corpus
contract. It does not change scanner runtime behavior in this milestone. The
project-owned databases under `data/` remain authoritative.

## Source governance

`corpus/sources/sources.json` is the only approved source-policy manifest. The
standard-library validator rejects unknown fields, unsafe identifiers, mutable
or incorrectly bound revisions, unapproved licenses, non-redistributable data,
missing attribution, malformed hashes, and untrusted first-party identities.
Validation performs no downloads and never executes adapters.

The current manifest authorizes only Skan's clean-room, first-party corpus. Nmap
and proprietary fingerprint databases are not accepted as source material.

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

## Verified migration mirror and loader gate

The populated files in `corpus/canonical/` are the governed, verified canonical
mirror of Skan's four first-party runtime databases. Their commit-marker manifest
binds every JSONL store's kind, count, and hash; readers reject incomplete or
mixed generations. They remain build-time inputs, not installed runtime data.

`data/service-probes.db`, `data/udp-probes.db`, `data/os-fingerprints.db`, and
`data/os-fingerprints-v6.db` remain the production and package authority in this
milestone. `build/corpus-runtime/` is generated and ignored. A runtime-authority
or packaging switch is deliberately deferred.

The offline lifecycle is:

```bash
python3 -m tools.corpus.cli import-runtime
python3 -m tools.corpus.cli compile --output-dir build/corpus-runtime
python3 -m tools.corpus.cli verify-roundtrip --output-dir build/corpus-runtime
make test-corpus-runtime
```

`verify-roundtrip` compares source runtime semantics, canonical records, and
deterministically compiled artifacts. `make test-corpus-runtime` then loads all
four generated databases through the production C++ `load_file` APIs and checks
coverage counts plus representative typed semantics. The command performs no
network access, scanning, adapter execution, or shell execution from corpus
tooling.

The source-policy rules above remain mandatory for all corpus changes: preserve
the pinned first-party source identity and license terms, and do not copy,
derive, or import Nmap or proprietary fingerprint data.
