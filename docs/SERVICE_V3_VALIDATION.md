# Service V3 HTTP/search/ZooKeeper validation

Baseline: published MQTT branch commit `6d73e88010849122d92970ff310797a6a32f8dc7`.
Engine comparison date: 2026-10-02. Runtime/canonical database bytes are unchanged.

## Regression boundaries

`tests/unit/detect/test_service_v3.cpp` covers complete and malformed HTTP
headers, body/header collisions, duplicate/empty Server fields, Jetty headers,
Content-Length conflicts,
framing conflict/overflow, informational responses, content encoding,
chunk extensions/trailers, every truncation boundary, JSON reordered/duplicate
decoded keys, Unicode/invalid UTF-8 and decoded-size boundaries, types, malformed numbers, depth limits,
request/status/content-type scope, distribution conflicts and partial or
uncorrelated ZooKeeper status reports. Expectations are project-authored
synthetic fixtures, not captured services.

Scheduler tests exercise every TCP split of a root response for both IPv4 and
IPv6, every split of malformed chunked responses, earlier-probe preservation,
EOF-delimited success and truncated content-length behavior. Existing
fallback-reset/timeout tests remain registered. Real loopback transport tests
exercise product/version extraction in both address families. The old detector
case containing only unfinished `HTTP/1.1 200` now deliberately expects UNKNOWN.
Output integration tests require evidence in JSON/XML/grepable and reject
inconsistent typed evidence.

## Repeatable checks

```bash
make -j2 all test test-comparison test-corpus-runtime check-version check-line-endings
make build/tests/fuzz/fuzz_packet_parsers.o
make build/benchmark_service_v3
./build/benchmark_service_v3
make test-service-v3-replay
```

The normal full suite passed locally, including 213 corpus tests, 46 comparison
tests, the generated-runtime production-loader gate, version and line-ending
checks. Privileged raw-network/interface cases reported explicit capability
skips in this environment; this run does not certify those skipped paths.
Independent code review findings were reproduced with failing tests and fixed:
segmentation-dependent stale HTTP evidence, Jetty header coverage, conflicting
ZooKeeper identity fields, empty-first duplicate Server and multibyte string
limits.

For the parser/matcher regressions and deterministic replay with GCC ASan/UBSan:

```bash
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
make -j2 BUILD_DIR=build/v3-sanitize build/v3-sanitize/test_service_v3 test-service-v3-replay \
  CXXFLAGS='-std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wno-maybe-uninitialized -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ./build/v3-sanitize/test_service_v3
```

Deterministic replay covers 245,442 inputs: original seeds, every truncation,
each single-byte substitution and an oversized response. ASan/UBSan passed
these inputs and the matcher regressions. LeakSanitizer cannot inspect the
restricted execution environment's `/proc` task information, so leak checking
was disabled for that local run. This is not a coverage-guided fuzz campaign.
`clang++` is unavailable locally; the full harness compiled with GCC. CI now
runs the libFuzzer harness for 30 seconds with the existing packet seeds and
new service seeds, caps inputs at 8,192 bytes, and retains logs/reproducers.
CI execution results must be read from the published commit's checks.

## Identical-workload microbenchmark

`benchmarks/service_v3_accuracy.cpp` is compiled unchanged against baseline and
current detector sources, using the same runtime database, C++20 and GCC -O2.
Each sample repeats 12 labeled fixtures 1,000 times; five samples are run.
These are 12 distinct synthetic observations, not 12,000 independent captures.

| Measure per 12 distinct fixtures | Baseline | Current |
| --- | ---: | ---: |
| Correct protocol classification | 4 | 12 |
| Wrong positive protocol classifications | 8 | 0 |
| Missed expected service classifications | 4 | 0 |
| Correct service/product/version tuple | 2 | 12 |
| Median time for 12,000 observations | 1.999 s | 0.158 s |
| Median correct tuples per second | 1,001 | 75,926 |

The workload includes case-varied Server headers, body lookalikes, reordered
OpenSearch JSON, malformed/encoded search-root collisions, invalid/partial HTTP
and incomplete or prefix-colliding ZooKeeper status. Wrong service labels on
positive cases can count as both a wrong positive and a missed expected label.
The throughput metric counts correct tuple outcomes, including correct
negatives, and grades no live network work. The result supports only this
regression workload; it does not establish general scanner performance,
real-world error rates, confidence calibration or superiority over Nmap.

## Primary derivation sources

- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html): HTTP framing and field syntax.
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html): JSON grammar and Unicode handling.
- [Elasticsearch root information API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-info): explicit root version and identity fields.
- [OpenSearch cluster information API](https://docs.opensearch.org/latest/api-reference/cluster-api/info/): distribution, version and identity fields.
- [ZooKeeper four-letter commands](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_zkCommands): read-only srvr behavior.

No Nmap or third-party fingerprint database content is used. The stricter
multi-field identity combinations, conservative unsupported cases and parser
limits are Skan engineering decisions, not claims that every standards-valid
peer response is supported.
