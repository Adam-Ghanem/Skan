# Versioned Comparison Baseline Design

## Goal

Make multi-scenario Skan-versus-Nmap evidence reproducible offline before any
performance tuning or superiority claim. A baseline must bind the exact ground
truth manifest and every raw scanner capture by SHA-256, describe the benchmark
profile and network condition for each scenario, and produce the same scorecard
without launching either scanner.

This milestone does not claim that Skan is better than Nmap. It makes later
top-1000 TCP measurements auditable and keeps the existing superiority gate
closed until the required profiles and quality evidence are implemented.

## Scope

- Add a strict schema-v1 baseline bundle loader under `tools/comparison/`.
- Support one or more scenarios in offline verification.
- Verify the manifest and raw Skan/Nmap captures before parsing them.
- Reject paths that are absolute, escape the bundle directory, or contain any
  symbolic-link component.
- Reject missing, duplicate, or extra scenario captures.
- Carry stable baseline, profile, condition, and lab metadata into reports.
- Add a `verify-baseline` CLI command that performs no network or process work.
- Check in a synthetic contract fixture only for tests. Do not present it as a
  measured controlled-lab baseline.

Live capture automation, schema-v2 superiority-profile gates, repeated
top-1000 timing trials, and scanner optimization are follow-up milestones.

## Bundle Layout

A bundle is rooted at the directory containing `baseline.json`:

```text
baseline.json
manifest.json
captures/
  skan/<scenario>.json
  nmap/<scenario>.xml
```

`baseline.json` has this shape:

```json
{
  "schema_version": 1,
  "baseline_id": "controlled-lab-v1",
  "manifest": {
    "path": "manifest.json",
    "sha256": "<64 lowercase hex characters>"
  },
  "environment": {
    "lab": "isolated-loopback",
    "machine": "x86_64",
    "network": "clean-lan"
  },
  "captures": [
    {
      "scenario_id": "top1000-clean-01",
      "profile": "top-1000-tcp-lan",
      "condition": "clean-lan",
      "skan": {"path": "captures/skan/top1000-clean-01.json", "sha256": "..."},
      "nmap": {"path": "captures/nmap/top1000-clean-01.xml", "sha256": "..."}
    }
  ]
}
```

All objects reject unknown fields and duplicate JSON keys. Identifiers use the
same bounded stable-identifier grammar as comparison manifests. Environment
keys are stable identifiers and values are bounded, non-empty strings.

## Integrity and Path Rules

The bundle descriptor is read with a 1 MiB limit. Manifest and capture files
retain their existing parser limits. Every referenced file is read once into a
bounded byte buffer, hashed, and only then parsed.

Artifact paths must be normalized relative POSIX paths. Empty components,
`.`/`..`, absolute paths, backslashes, and symbolic-link components are
rejected. The bundle root is opened before `baseline.json`; the descriptor and
all artifacts are then opened relative to that same held directory descriptor
with link following disabled. Descriptors and artifacts must be regular files
and are opened non-blocking before inspection. The same final artifact
descriptor is bounded, hashed, and parsed. Each underlying file may appear only
once. The manifest's scenario IDs and the capture scenario IDs must match
exactly.

Hash mismatches, malformed captures, symlink escapes, and incomplete scenario
coverage fail the whole verification. No partial scorecard is written.

## Verification Flow

1. Parse and validate `baseline.json` without running external commands.
2. Open each path relative to a held bundle-root descriptor without following
   symbolic links.
3. Read bounded bytes and verify SHA-256.
4. Parse the verified manifest and captures with the existing strict adapters.
5. Build one scanner-run mapping per scenario.
6. Add deterministic environment fields plus a structured per-scenario mapping
   for the baseline ID, profiles, conditions, and
   `execution=offline-versioned-baseline`.
7. Atomically write JSON and Markdown scorecards.

The legacy single-scenario `score` command remains available. The new command
is:

```sh
python3 -m tools.comparison.cli verify-baseline \
  --bundle path/to/baseline.json \
  --json scorecard.json \
  --markdown scorecard.md
```

## Safety and Claim Policy

- Verification never starts a process or opens a network connection.
- Live scans remain restricted to manifests carrying the exact
  `operator-controlled-lab` authorization marker.
- Bundle metadata is descriptive evidence, not proof that a network condition
  was physically enforced.
- Schema-v1 scoring continues to fail the required-profile gate. A valid bundle
  can report measurements but cannot unlock a superiority claim.
- The repository test fixture is synthetic and must be labelled as such.

## Acceptance Criteria

- A valid two-scenario bundle produces one deterministic scorecard containing
  both scanner runs and stable profile/condition metadata.
- Any byte change to a bound manifest or capture causes a hash failure.
- Traversal, absolute paths, every symlink component, unknown fields, duplicate keys,
  duplicate artifacts, and missing/extra scenario captures are rejected.
- `verify-baseline` does not call `run_suite`.
- Existing comparison, corpus, and runtime-corpus gates remain green.
- The full aggregate suite is attempted and any environment-only failure is
  reported without claiming success.
