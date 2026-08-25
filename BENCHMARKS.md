# Offline Benchmark Report

**Author:** Manus AI
**Date:** 2026-08-25
**Revision under test:** `2a9e992b20e0e12dcee430a5e8169f6f443621e1` plus the audit hardening changes recorded in the working tree.

## Methodology

The opt-in `make benchmark` target builds `benchmarks/offline_benchmark.cpp` against the production library without the CLI entry point. It performs no network I/O. Each stage is executed five times for each target count; the reported wall time is the median sample and `p95_wall_ms` is the maximum of the five samples. Peak RSS is the Linux process `VmHWM` observed after the stage. The workload uses deterministic IPv4 addresses in documentation space, one TCP port per target, project-owned offline transports, the existing schedulers, the existing orchestrator, and the canonical JSON/XML writers.

The benchmark measures target expansion, TCP scheduling, UDP scheduling, service scheduling, OS scheduling, full offline orchestration, and serialization. The OS stage sends twelve deterministic logical probes per target through `RecordingOSProbeTransport`; no packets leave the process. Results are machine-specific and should be used for regression comparison rather than as universal throughput claims.

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
