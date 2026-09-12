# Intelligence Database v2 Migration Roadmap

**Mission:** Maintain a governed, reproducible canonical mirror of Skan's
first-party runtime intelligence databases while keeping production behavior
unchanged until a separately approved authority switch.

## Current status — complete verified mirror

The active-service, service-matcher, UDP, IPv4 OS, and IPv6 OS corpus families
are imported into populated schema-v2 stores under `corpus/canonical/`. The
stores have a deterministic commit-marker manifest and are verified against the
pinned first-party source policy. The deterministic compiler emits the existing
runtime grammars and the production C++ loaders acceptance-test every generated
artifact.

```text
data/*.db -> canonical v2 -> validate -> compile -> real C++ load_file gate
```

Run the offline gate with:

```bash
python3 -m tools.corpus.cli import-runtime
python3 -m tools.corpus.cli compile --output-dir build/corpus-runtime
python3 -m tools.corpus.cli verify-roundtrip --output-dir build/corpus-runtime
make test-corpus-runtime
```

`build/corpus-runtime/` is generated and ignored. The canonical files are the
governed verified mirror, but `data/service-probes.db`, `data/udp-probes.db`,
`data/os-fingerprints.db`, and `data/os-fingerprints-v6.db` remain the runtime
and package authority. This milestone does not change `RuntimePaths`, install
rules, package contents, or scanner database selection.

## Source governance

`corpus/sources/sources.json` pins the allowed clean-room first-party source,
identity, revision, hash, license, and attribution. Corpus tooling is offline,
uses only the Python standard library, and executes neither adapters nor shell
commands. Nmap and proprietary fingerprint databases must not be copied,
derived, or imported.

## Deferred authority switch

Before canonical data may replace `data/*.db` as production/package authority,
an approved later change must define a controlled generation path, package
verification, rollback behavior, startup and resident-memory benchmarks, and
the runtime-selection change. The current real-loader round-trip gate is
evidence of equivalence, not authorization for that switch.
