# OS evidence confidence

Skan's OS confidence is a weighted evidence score, not a calibrated probability
that a host runs a particular operating system. Runtime fingerprints describe
generic stack styles; production accuracy requires a separate labelled benchmark.

For each candidate, confidence is the sum of weights of matching observed fields
divided by the sum of weights of all fields configured in that fingerprint.
Weights and category thresholds are defined in `src/osdetect/os_matcher.cpp` and
`include/osdetect/os_matcher.hpp`.

| Score | Category |
| --- | --- |
| Below 0.30 | No match |
| 0.30 to below 0.60 | Low confidence |
| 0.60 to below 0.85 | Possible match |
| 0.85 and above | Strong match |

Absent, timed-out, invalid, and unsupported observations contribute no matched
weight. They remain in `unavailable_fields`, separately from observed
contradictions in `mismatched_fields`. For example, a profile requiring TTL,
window, MSS, SACK, and timestamps scores about 0.18 when only TTL matches;
the old available-fields denominator incorrectly produced 1.0.

Strong matches sort by profile specificity first, then confidence. This keeps a
strongly supported specific profile ahead of a fully supported broad fallback.
Other candidates sort by confidence, then specificity; name and ID break ties
deterministically. A weak specific candidate cannot outrank a strong fallback.

Candidates classified as no match remain available in the diagnostic match list.
The scheduler leaves the reported host OS identity empty when the best candidate
is no match. Scan completion still describes whether probes completed, not
whether an OS was identified. The same scoring policy applies to IPv4 and IPv6.

Regression coverage in `test_os_matcher` and `test_os_scheduler` checks sparse
evidence, unsupported fields, contradictions, evidence growth, ranking, and
suppression of unsupported host identities.
Report-builder and terminal regressions verify that the same candidate ordering
reaches machine outputs and that the displayed fingerprint belongs to the
selected classification. An unclassified terminal summary displays `OS: unknown`.

## Validation (2026-10-03)

- Full build and C++ suite: `make all test`.
- Corpus contracts and comparison: 213 corpus tests and 46 comparison tests.
- Generated database round trip and production loader: `make test-corpus-runtime`.
- Release consistency: `make check-version check-line-endings`.
- Focused matcher/scheduler tests passed GCC ASan and UBSan with
  `halt_on_error=1`; leak detection was disabled in this restricted environment.
  Sanitized executables were copied into the top-level `build` directory so
  runtime data resolution used the repository's fingerprint databases.

Raw network capability tests retain their explicit environment skips. These
checks verify behavior and regressions; they do not establish real-world OS
accuracy or a ranking against other scanners.
