# Offline Benchmark Report

**Author:** Manus AI
**Date:** 2026-08-26
**Revision under test:** Phase 19 working tree; the final commit hash is recorded in the delivery report.

## Methodology

The opt-in `make benchmark` target builds `benchmarks/offline_benchmark.cpp` against the production library without the CLI entry point. It performs no network I/O. Each stage is executed five times for each target count; the reported wall time is the median sample and `p95_wall_ms` is the maximum of the five samples. Peak RSS is the Linux process `VmHWM` observed after the stage. The workload uses deterministic IPv4 addresses in documentation space, one TCP port per target, project-owned offline transports, the existing schedulers, the existing orchestrator, and the canonical JSON/XML writers.

The benchmark measures IPv4, IPv6, and mixed target expansion; IPv4 and IPv6 packet parsing; NDP parsing; correlation lookup; TCP/UDP/service scheduling; IPv6 OS parsing/matching/scheduling; mixed scheduling; full IPv4/IPv6/mixed offline orchestration; OS scheduling; and serialization. The OS stage sends twelve deterministic logical probes per target through `RecordingOSProbeTransport`; no packets leave the process. Each row reports five-sample median and maximum-of-five p95, throughput, and peak Linux `VmHWM`. Results are machine-specific and should be used for regression comparison rather than as universal throughput claims.

## Results

| Stage | Targets | Median wall (ms) | p95 wall (ms) | Operations/s | Peak RSS (KiB) | Operations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Target expansion | 100 | 0.004 | 0.015 | 27,739,251 | 2,168 | 100 |
| TCP scheduler | 100 | 1.442 | 1.548 | 69,348 | 4,472 | 100 |
| UDP scheduler | 100 | 1.463 | 1.502 | 68,363 | 4,472 | 100 |
| Service scheduler | 100 | 1.658 | 1.726 | 60,296 | 5,168 | 100 |
| OS scheduler | 100 | 17.819 | 18.183 | 67,345 | 5,676 | 1,200 |
| Full orchestrator | 100 | 1.611 | 1.773 | 62,083 | 5,676 | 100 |
| JSON serialization | 100 | 0.051 | 0.055 | 1,965,525 | 5,676 | 100 |
| XML serialization | 100 | 0.024 | 0.032 | 4,085,468 | 5,676 | 100 |
| Target expansion | 1,000 | 0.033 | 0.071 | 30,581,040 | 3,980 | 1,000 |
| TCP scheduler | 1,000 | 4.775 | 4.878 | 209,417 | 5,224 | 1,000 |
| UDP scheduler | 1,000 | 4.962 | 5.025 | 201,542 | 5,740 | 1,000 |
| Service scheduler | 1,000 | 5.247 | 5.569 | 190,575 | 6,400 | 1,000 |
| OS scheduler | 1,000 | 50.922 | 56.036 | 235,655 | 10,540 | 12,000 |
| Full orchestrator | 1,000 | 7.292 | 7.612 | 137,130 | 10,540 | 1,000 |
| JSON serialization | 1,000 | 0.534 | 0.549 | 1,874,210 | 10,540 | 1,000 |
| XML serialization | 1,000 | 0.230 | 0.239 | 4,353,163 | 10,540 | 1,000 |
| Target expansion | 10,000 | 0.398 | 0.811 | 25,154,575 | 5,276 | 10,000 |
| TCP scheduler | 10,000 | 42.488 | 55.129 | 235,362 | 11,036 | 10,000 |
| UDP scheduler | 10,000 | 41.082 | 41.856 | 243,414 | 12,904 | 10,000 |
| Service scheduler | 10,000 | 45.431 | 46.708 | 220,115 | 19,112 | 10,000 |
| OS scheduler | 10,000 | 544.160 | 560.699 | 220,523 | 54,044 | 120,000 |
| Full orchestrator | 10,000 | 100.455 | 106.557 | 99,547 | 54,044 | 10,000 |
| JSON serialization | 10,000 | 5.540 | 6.034 | 1,805,177 | 54,044 | 10,000 |
| XML serialization | 10,000 | 2.439 | 2.920 | 4,099,209 | 54,044 | 10,000 |

## Interpretation

The measured offline stages scale approximately linearly over 100 to 10,000 targets. The OS scheduler is the dominant isolated stage because it performs twelve probe families per target and retains evidence for matching; at 10,000 targets it completes 120,000 logical operations in a median 544.160 ms. The full orchestrator remains below 107 ms at 10,000 targets for its single TCP-port offline workload because that workload does not enable UDP, service detection, or OS detection.

The service scheduler’s prior duplicate suppression was an O(N²) linear scan over previously seen target/port pairs. It now uses a hashed composite key while preserving first-seen ordering. Target normalization also no longer performs a redundant second deduplication pass after expansion has already guaranteed uniqueness. These changes are included in the audit working tree and should be measured again on the same host after future changes.

The benchmark previously exposed a misuse of the low-level `OSScheduler` API: the benchmark passed a temporary database to a scheduler that intentionally borrows its database. The harness now keeps the database alive for the scheduler’s full lifetime, and the API contract is documented in the OS and service scheduler headers. Production-facing `OSDetector` and `ServiceDetector` already own their databases by value.

## Reproduction

Run the following commands from the repository root:

```sh
make benchmark
./build/benchmark_offline 100
./build/benchmark_offline 1000
./build/benchmark_offline 10000
```

The benchmark target is opt-in and is not part of the ordinary test recipe. It must remain offline and must not be changed to generate public-target traffic.

## Phase 19 required matrix

The benchmark driver now emits the following required rows: `target-expansion`, `ipv6-target-expansion`, `mixed-target-expansion`, `ipv4-receiver-parser`, `ipv6-receiver-parser`, `ipv6-ndp-parser`, `correlation-lookup`, `ipv6-os-matcher`, `ipv6-os-scheduler`, `mixed-os-scheduler`, `full-ipv4-orchestrator`, `full-ipv6-orchestrator`, and `mixed-orchestrator`. The 1,000- and 10,000-target runs exercise the corresponding bounded workloads; the correlation row uses the existing typed IPv6 `CorrelationTable` with deterministic insertion and lookup.

These are offline measurements only. They validate algorithmic scaling and resource behavior, not permission to inject or capture live packets. AF_PACKET-dependent integration remains capability-gated and is reported separately as `SKIPPED`/`UNAVAILABLE` when the host denies raw packet access.

## Phase 19 measurements

| Stage | Targets | Median wall (ms) | p95 wall (ms) | Operations/s | Peak RSS (KiB) | Operations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Target expansion | 1,000 | 0.131 | 0.200 | 7,657,730 | 4,368 | 1,000 |
| IPv6 target expansion | 1,000 | 0.209 | 0.258 | 4,774,272 | 4,620 | 1,000 |
| Mixed target expansion | 1,000 | 0.291 | 0.416 | 3,437,135 | 4,940 | 1,000 |
| IPv4 packet parser | 1,000 | 0.065 | 0.067 | 15,499,791 | 4,940 | 1,000 |
| IPv6 packet parser | 1,000 | 0.070 | 0.082 | 14,227,584 | 4,940 | 1,000 |
| NDP parser | 1,000 | 0.072 | 0.072 | 27,832,283 | 4,940 | 2,000 |
| Correlation lookup | 1,000 | 0.271 | 0.279 | 3,691,099 | 15,136 | 1,000 |
| IPv6 OS matcher | 1,000 | 1.427 | 1.971 | 2,102,475 | 4,940 | 3,000 |
| IPv6 OS scheduler | 1,000 | 51.820 | 52.900 | 231,570 | 14,812 | 12,000 |
| Mixed OS scheduler | 1,000 | 52.244 | 53.087 | 229,694 | 14,812 | 12,000 |
| Full IPv4 orchestrator | 1,000 | 7.270 | 7.844 | 137,551 | 15,136 | 1,000 |
| Full IPv6 orchestrator | 1,000 | 1,166.051 | 1,173.563 | 858 | 29,708 | 1,000 |
| Mixed orchestrator | 1,000 | 1,162.880 | 1,188.274 | 860 | 29,708 | 1,000 |
| Target expansion | 10,000 | 2.064 | 2.856 | 4,845,957 | 7,056 | 10,000 |
| IPv6 target expansion | 10,000 | 2.560 | 2.596 | 3,906,816 | 7,376 | 10,000 |
| Mixed target expansion | 10,000 | 3.821 | 3.923 | 2,616,873 | 11,392 | 10,000 |
| IPv4 packet parser | 10,000 | 0.675 | 0.677 | 14,816,527 | 11,392 | 10,000 |
| IPv6 packet parser | 10,000 | 0.718 | 0.747 | 13,926,490 | 11,392 | 10,000 |
| NDP parser | 10,000 | 0.736 | 0.747 | 27,170,443 | 11,392 | 20,000 |
| Correlation lookup | 10,000 | 3.002 | 3.148 | 3,331,626 | 93,664 | 10,000 |
| IPv6 OS matcher | 10,000 | 13.807 | 14.807 | 2,172,872 | 11,392 | 30,000 |
| IPv6 OS scheduler | 10,000 | 523.177 | 535.059 | 229,368 | 92,248 | 120,000 |
| Mixed OS scheduler | 10,000 | 525.875 | 527.766 | 228,191 | 92,288 | 120,000 |
| Full IPv4 orchestrator | 10,000 | 106.229 | 112.219 | 94,137 | 93,664 | 10,000 |
| Full IPv6 orchestrator | 10,000 | 11,865.634 | 11,932.637 | 843 | 245,312 | 10,000 |
| Mixed orchestrator | 10,000 | 11,809.484 | 12,077.619 | 847 | 245,312 | 10,000 |

These measurements confirm that the expanded IPv6 and mixed orchestration rows execute entirely offline. The substantially higher IPv6 and mixed orchestrator time reflects the enabled OS scheduler’s twelve logical probes per host; it is not a live-network timing claim.

## Phase 20 Benchmark Extension

The offline benchmark now includes hostname resolution using `localhost` with bounded limits; IPv4/IPv6/mixed target expansion; IPv4/IPv6 packet receivers; TCP, UDP, ICMP, ICMPv6, and NDP parser rows; correlation insert, lookup, and deadline cleanup; timer scheduling and cancellation; IPv4 and IPv6 OS matching and scheduling; TCP and UDP service matching; full IPv4/IPv6/mixed orchestration; and normal, JSON, XML, and grepable serialization. All fixtures are offline or loopback-safe and no public network target is contacted.

The correlation stress unit test inserts and cleans 100,000 typed entries. The output integration test serializes a deterministic mixed-family 10,000-host report through JSON and XML. Results are reported as CSV with median and p95 wall time, operations per second, peak resident set size, and operation count. The unusually larger full IPv6/mixed orchestration rows reflect bounded offline OS scheduling for every target and are not presented as network throughput.
