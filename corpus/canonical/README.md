# Canonical corpus staging

These schema-v2 JSONL stores are intentionally empty migration staging areas.
The runtime databases under `data/` remain authoritative until a later compiler
milestone proves full round-trip compatibility through the real C++ loaders.

Empty stores are accepted only when tooling explicitly opts into
migration-staging mode. Production validation rejects an empty corpus.
