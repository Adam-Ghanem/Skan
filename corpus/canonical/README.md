# Canonical corpus

These schema-v2 JSONL stores are the deterministic import of the reviewed,
first-party runtime databases under `data/`. Regenerate them offline with
`python -m tools.corpus.cli import-runtime` and validate the semantic
round-trip with `python -m tools.corpus.cli verify-roundtrip`.

The scanner continues to select the reviewed runtime databases under `data/`.
Switching packaged runtime selection to compiler output remains deferred until
the real C++ loader gate and lifecycle documentation land.
