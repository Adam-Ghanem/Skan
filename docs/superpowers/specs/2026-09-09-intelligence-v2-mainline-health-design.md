# Intelligence v2 Mainline Health Design

## Objective

Restore the current Skan mainline after the clean-room OS corpus expansion without replacing one brittle record-count assertion with another. The regression gate must describe required corpus behavior: the built-in database loads successfully, includes both address families, retains canonical representative records, and exposes unique stable identifiers.

This increment is deliberately narrow. It does not add fingerprints, change matcher scoring, or introduce the Intelligence Database v2 schema/compiler. Those are separate, reviewable increments after main is green.

## Current failure

The production corpus now contains independently maintained IPv4 and IPv6 records, but `tests/unit/db/test_os_db.cpp` still requires exactly eight merged records and assumes IPv6 starts at a fixed vector index. Current main CI therefore aborts before later OS tests execute. Several later tests also name profiles removed by the expansion.

## Design

The built-in corpus test will inspect records by semantic identity rather than position or total count. It will require:

- successful built-in loading;
- at least one IPv4 and one IPv6 record;
- globally unique, non-empty IDs and names in the merged database;
- non-empty vendor, family, and signatures for every record;
- address-family values limited to IPv4 or IPv6;
- presence of the canonical representative IDs `skan-v4-linux-modern-64240` and `skan-v6-linux-modern-64240` with the expected family.

Matcher, scheduler, and injected-transport tests will be aligned to those representative records. They will continue to assert ranking, confidence, state, evidence, and address family; only stale corpus identities will change.

## Error and security properties

Parser rejection tests for duplicate names, duplicate fields, missing class metadata, invalid values, invalid ranges, unknown fields, oversized input, and IPv6 family metadata remain mandatory. This change must not loosen database validation or cause a test to accept an arbitrary corpus size.

All validation is offline. No network targets are contacted.

## Acceptance criteria

- The pre-change focused OS regression suite fails for the known stale corpus contract.
- The built-in corpus test has no fixed production corpus count or positional family assertion.
- Duplicate merged IDs and names are detected by the test.
- Both address families and the two canonical Linux-family representatives are required.
- OS matcher, scheduler, and injected detection tests pass against the current corpus.
- Full `make test`, release/debug builds, ASan, UBSan, line-ending, and version checks pass locally where supported.
- GitHub CI is green before merge.
