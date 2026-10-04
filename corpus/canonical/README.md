# Canonical first-party runtime mirror

This directory contains the schema-v2 deterministic mirror of Skan's reviewed,
first-party runtime databases. `manifest.json` binds exactly four stores by
kind, count, and hash:

- `active-probes.jsonl`;
- `services.jsonl`;
- `os.jsonl`; and
- `udp.jsonl`.

The empty `products.jsonl` file is retained as a backward-compatible
enrichment placeholder. It is not manifest-bound and is not a runtime database.

Regenerate the mirror offline with
`python -m tools.corpus.cli import-runtime` and validate the deterministic
semantic round trip with
`python -m tools.corpus.cli verify-roundtrip --output-dir build/corpus-runtime`.
The compiled results correspond to the packaged `data/*.db` runtime authority.

Generated public-source intelligence is isolated under `corpus/external/` and
has its own manifest, source locks, statistics, and notice checks. Those
external records are not loaded by `skan -sV`. Verify both authority boundaries
with `make -f GNUmakefile corpus-external-verify`.

Nmap remains comparator-only; no Nmap corpus material is imported here.
