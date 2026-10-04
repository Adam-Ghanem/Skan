# External Corpus Integrity Design

## Intent

Skan must preserve its first-party runtime fingerprint mirror and its generated public-source intelligence at the same time. A refresh must never overwrite first-party service rules, and repository statistics must describe the records that are actually committed.

This milestone repairs the storage and verification boundary only. It does not load the external service or web corpus into the scanner runtime; that requires a separately bounded runtime-index milestone with collision, memory, and latency evidence.

## Current Failure

Two independent producers publish a file named `services.jsonl` into `corpus/canonical/`:

- the first-party runtime round-trip writes Skan's active runtime matchers; and
- the external refresh writes Rapid7 Recog passive matchers.

The first-party reconciliation later replaced the external service store while `corpus/reports/external-stats.json` continued to claim 2,302 external service matchers. The web and registry stores survived only because their filenames did not collide. The existing external verification target validates the mixed canonical directory but does not bind the external statistics to external store bytes.

## Storage Boundaries

`corpus/canonical/` is the authoritative first-party runtime mirror. Its manifest continues to bind the four runtime stores:

- `active-probes.jsonl`
- `services.jsonl`
- `os.jsonl`
- `udp.jsonl`

The existing empty `products.jsonl` remains an unbound first-party enrichment placeholder for backward compatibility. It is not external intelligence and is not a runtime database.

`corpus/external/` is the authoritative generated public-source corpus. It contains deterministic stores for every supported external record kind plus `manifest.json`. External stores retain their established filenames, including `services.jsonl`, because the separate root removes the collision without changing the external record schema.

The external store set is exact:

- `cpe.jsonl`
- `devices.jsonl`
- `os.jsonl`
- `products.jsonl`
- `registry.jsonl`
- `services.jsonl`
- `udp.jsonl`
- `web.jsonl`

An external refresh writes only under its staging output root. The repository workflow copies generated external stores into `corpus/external/`; it never copies them into `corpus/canonical/`.

## External Manifest

`corpus/external/manifest.json` uses schema version 1 and contains one entry for every external store. Each entry binds:

- the exact SHA-256 of the committed file bytes;
- the total record count; and
- the count for each canonical record kind in that file.

Serialization is canonical JSON with sorted keys, compact separators, UTF-8, and one trailing LF. Empty stores are present and bound, so missing data cannot be confused with an intentionally empty source class.

## Verification

Offline verification performs all of the following:

1. rejects a missing, unsafe, oversized, malformed, or non-canonical external manifest;
2. requires the exact external store set and rejects untracked extra JSONL stores;
3. validates every record against `corpus/sources/external-sources.json`;
4. rejects duplicate semantic IDs across stores and unresolved identity conflicts;
5. recomputes every file hash, record count, and kind count and compares them with the manifest;
6. recomputes the externally derivable fields in `corpus/reports/external-stats.json` and rejects stale statistics;
7. requires a source lock for every represented external source and checks provenance revision, URL, license policy, and source hash against that lock; and
8. regenerates third-party notices from represented sources and compares them byte-for-byte with `corpus/THIRD_PARTY_NOTICES.md`.

The verifier is read-only, deterministic, offline, and returns a concise summary on success. It never downloads data or mutates the repository.

## Refresh and Publication

`tools.corpus.bulk_refresh` writes generated data under `<output-root>/external/`, locks under `<output-root>/locks/`, statistics at `<output-root>/stats.json`, and notices at `<output-root>/THIRD_PARTY_NOTICES.md`. It generates the external manifest after writing all stores.

All record totals, including `detection_records`, are computed from the merged records that were actually written. Raw adapter input counts must not survive deduplication into published statistics.

The refresh workflow compares two complete generations byte-for-byte, installs the external directory, locks, statistics, and notices, then runs offline verification before committing. The workflow's branch trigger is updated to the maintained mainline workflow context rather than the obsolete historical feature branch.

## Recovery

The missing 2,302 Recog service matchers are recovered from commit `fac5264`, the last repository commit whose generated external statistics and service store agree. Recovery is accepted only after the current external schema, source policy, lock, manifest, statistics, and notice checks all pass. No Nmap code or database content is used.

## Compatibility and Security

- First-party runtime compilation and scanner behavior do not change in this milestone.
- Existing external canonical record JSON is not rewritten except for repository location.
- No runtime network access is introduced.
- No untrusted code is executed.
- No public target is scanned.
- Source provenance and redistribution policy remain mandatory.
- The verifier uses bounded manifest/stat/lock parsing and rejects symlinks for governed files.

## Acceptance Criteria

- A refresh cannot overwrite `corpus/canonical/services.jsonl`.
- `corpus/external/services.jsonl` contains the recovered 2,302 Recog records.
- External web and registry stores live under `corpus/external/`.
- Manifest hashes and counts match every external store.
- External statistics match the committed stores.
- `detection_records` is 17,824 for the recovered generation, not the stale pre-deduplication value 17,917.
- Deleting or changing an external store, manifest entry, lock, or notice makes verification fail with a specific error.
- Two fixture refreshes are byte-identical.
- Existing first-party corpus tests remain green.
- Documentation describes the two authorities and does not claim external records are active runtime detection rules.
