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

## Migration gate

The empty files in `corpus/canonical/` are explicitly migration staging. Empty
stores are rejected unless tooling opts into staging mode. They are not shipped
as runtime databases and are not evidence of corpus coverage.

A later increment must prove this complete path before generated data can become
authoritative:

```text
runtime DB -> canonical v2 -> reload -> validate -> compile -> real C++ loaders
```

That gate must compare deterministic semantic manifests for service probes,
match rules, UDP definitions, and both IPv4 and IPv6 OS fingerprints. It must
also resolve cross-record references and conflicts without weakening current
loader bounds.

### UDP vertical slice

UDP is the first migration slice because its current runtime grammar is small,
bounded, and exposes a direct ordered definition model. `tools/corpus/legacy_udp.py`
mirrors the production `UDPProbeDatabase::parse` semantics needed by the owned
corpus, normalizes payload hexadecimal, assigns deterministic declaration order,
binds each record to the pinned first-party source policy, and compiles canonical
records back into the current runtime grammar.

`tools/corpus/udp_pipeline.py` verifies both serialization boundaries:

```text
data/udp-probes.db
  -> canonical UDP records
  -> deterministic JSONL reload
  -> generated udp-probes.db
  -> semantic reload
```

The corpus test suite also compiles a narrow test helper against the production
`src/portscan/udp_scan.cpp` implementation and requires the real C++ loader to
produce the same ordered definitions, port index behavior, default probe,
payload bytes, protocol hints, and response bounds for the legacy and generated
runtime databases.

This slice does **not** make canonical UDP data authoritative yet. The checked-in
`data/udp-probes.db` remains the runtime source of truth until all required
corpus families have migration/compiler coverage, cross-record validation and
manifest generation are complete, packaging consumes generated artifacts, and
the full migration gate is approved.
