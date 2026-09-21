# Reproducible Scanner Comparison Baselines

Skan's comparison tool can verify a versioned, multi-scenario evidence bundle
without starting Skan, Nmap, or any network operation. The bundle binds the
ground-truth manifest and every raw capture by SHA-256, then feeds the verified
bytes into the same strict parsers and scorecard generator used by the
single-scenario comparison command.

This mechanism records evidence. It does not by itself prove that a lab
condition was enforced, and schema version 1 cannot authorize a public
superiority claim. The scorecard's required-profile gate therefore remains
closed.

## Bundle layout

Keep all referenced files below the directory containing `baseline.json`:

```text
controlled-lab-v1/
  baseline.json
  manifest.json
  captures/
    skan/
      clean-01.json
    nmap/
      clean-01.xml
```

Artifact paths in `baseline.json` are normalized relative POSIX paths. Absolute
paths, `.` or `..` components, backslashes, duplicate files, and every symbolic
link component are rejected. Verification holds an open bundle-root descriptor,
opens `baseline.json` itself relative to that descriptor, then walks each
artifact component without following links. Descriptors and artifacts must be
regular files and are opened non-blocking before inspection. A concurrent path
rename therefore cannot separate the descriptor from its artifacts or redirect
verification outside the held bundle directory.

The descriptor format is:

```json
{
  "schema_version": 1,
  "baseline_id": "controlled-lab-v1",
  "manifest": {
    "path": "manifest.json",
    "sha256": "<lowercase SHA-256>"
  },
  "environment": {
    "lab": "isolated-loopback",
    "machine": "x86_64",
    "network": "clean-lan"
  },
  "captures": [
    {
      "scenario_id": "clean-01",
      "profile": "top-1000-tcp-lan",
      "condition": "clean-lan",
      "skan": {
        "path": "captures/skan/clean-01.json",
        "sha256": "<lowercase SHA-256>"
      },
      "nmap": {
        "path": "captures/nmap/clean-01.xml",
        "sha256": "<lowercase SHA-256>"
      }
    }
  ]
}
```

Every scenario in `manifest.json` must have exactly one capture entry, and no
capture may name an undeclared scenario. Each entry requires both Skan JSON and
Nmap XML. Profile and condition identifiers are preserved both as deterministic
summary metadata and as a structured per-scenario mapping in the scorecard.

## Creating the integrity bindings

Finish and freeze the manifest and raw captures before calculating hashes. On a
system with GNU coreutils, calculate each digest with:

```sh
sha256sum manifest.json captures/skan/*.json captures/nmap/*.xml
```

Copy the exact lowercase digests into `baseline.json`. Do not reformat or edit a
bound artifact afterward; any byte change correctly invalidates the bundle.

## Offline verification

Run the verifier from the repository root:

```sh
python3 -m tools.comparison.cli verify-baseline \
  --bundle path/to/controlled-lab-v1/baseline.json \
  --json scorecard.json \
  --markdown scorecard.md
```

The command verifies paths, sizes, hashes, scenario coverage, and parser
invariants before atomically writing both reports. Failure writes no partial
scorecard pair. The report includes the baseline ID, the sorted profile and
condition sets, the scenario-to-profile/condition mapping, scanner versions,
raw timing samples, exclusions, and the canonical manifest digest. Environment
values cannot contain line, control, or Unicode format characters and are
rendered using Markdown code spans that embedded backticks cannot terminate.

`tests/comparison/fixtures/baseline-v1` is synthetic parser and contract data.
It exists only to test deterministic offline verification. It is not a lab
measurement, performance result, or evidence that Skan outperforms Nmap.

## Current claim boundary

A valid schema-v1 bundle still reports `NOT ELIGIBLE` because the comparison
engine does not yet attest all required benchmark profiles or quality gates.
The next measurement milestone must add a versioned top-1000 TCP lab profile,
repeat timing samples, per-condition correctness gates, modern-service evidence,
and verified CI quality evidence before a superiority claim can be considered.
