# Contributing to Skan

Contributions should preserve Skan's single-reactor architecture, bounded resource model, deterministic results, typed failures, and explicit transport selection.

## Local checks

```bash
make clean
make -j2
make test-corpus
make test-corpus-runtime
make test
bash tests/integration/cli/test_nmap_compat.sh
make asan
make ubsan
make coverage
make benchmark
make fuzz
make clean
```

Raw-network changes also require the isolated private-lab acceptance documented in [Privileged Private-Lab Validation](docs/PRIVILEGED_VALIDATION.md).

## Pull requests

Keep changes focused, add deterministic regression coverage, document capability boundaries, and distinguish offline, loopback, isolated-lab, and real-network evidence. Do not claim a test or capability that did not run.

Do not introduce hidden fallback transports, unbounded target or response handling, public-target tests, shell execution from production code, evasion, exploitation, credentials, or persistence.

Corpus changes must pass `make test-corpus`. Approved source policy lives in
`corpus/sources/sources.json`; never copy Nmap or proprietary fingerprint data.
For a runtime-corpus change, also run `make test-corpus-runtime`: it performs
the offline canonical import/compile/verify round trip and loads generated
artifacts through the production C++ loaders. The populated schema-v2 stores in
`corpus/canonical/` are the governed verified mirror, while `data/*.db` remains
the production and package authority. `build/corpus-runtime/` is generated and
ignored; changing runtime authority is outside this milestone.
