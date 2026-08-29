# Contributing to Skan

Contributions should preserve Skan's single-reactor architecture, bounded resource model, deterministic results, typed failures, and explicit transport selection.

## Local checks

```bash
make clean
make -j2
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
