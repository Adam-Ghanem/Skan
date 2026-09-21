# Skan Core Superiority Foundation Design

**Date:** 2026-09-20
**Status:** Approved for implementation
**Target:** Linux-first authorized network inventory and reconnaissance

## 1. Purpose

Skan will not claim to be better than Nmap because it exposes more flags or
because a synthetic throughput number is larger. The first superiority
milestone creates an evidence-backed path to outperform Nmap on the core Linux
inventory workflow: host and port state accuracy, modern service identification,
scan duration, result explainability, and operational stability.

The milestone keeps Skan's existing single-reactor C++20 architecture. It adds
a deterministic differential benchmark and closes correctness gaps that would
invalidate a comparison. Nmap is an optional black-box comparator in controlled
tests; it is never a runtime dependency and none of its licensed fingerprints
or source code are imported.

## 2. Current Baseline

At the start of this milestone, Skan already provides:

- one epoll-backed `IOEngine` shared across scan stages;
- IPv4 and IPv6 target handling;
- TCP Connect, TCP SYN, and UDP scans;
- adaptive scheduling and RTT estimation;
- service and OS evidence pipelines;
- deterministic normal, JSON, XML, and grepable output;
- sanitizers, fuzz infrastructure, packaging validation, and a green `main` CI;
- a canonical project-owned intelligence corpus.

The main limitations relevant to a superiority claim are:

- no reproducible Skan-versus-Nmap scorecard tied to known ground truth;
- a much smaller service and OS intelligence corpus than Nmap;
- open correctness contracts for bounded UDP database loading and selected
  modern service responses;
- several unmerged or intentionally-red pull requests that cannot be treated as
  released behavior;
- local raw-network validation depends on Linux capabilities unavailable in
  some sandboxes.

## 3. Scope

### 3.1 Included

1. A deterministic, standard-library-only comparison tool for controlled lab
   results.
2. A versioned scenario manifest containing explicit target, protocol, port,
   and expected evidence.
3. Adapters for Skan structured output and Nmap XML output.
4. Accuracy metrics for port states and service identity, plus wall-clock timing
   summaries.
5. Machine-readable JSON and human-readable Markdown scorecards.
6. Fail-closed handling of malformed, incomplete, timed-out, or incompatible
   comparator results.
7. Bounded runtime loading of the UDP intelligence database.
8. Focused modern-service correctness fixtures whose expected identity comes
   from authoritative protocol or vendor behavior, not from Nmap data.
9. CI tests for the comparison model, parsers, scoring, command construction,
   bounded I/O, and deterministic report generation.

### 3.2 Excluded

- public-target automation or benchmark traffic;
- stealth, spoofing, decoys, fragmentation attacks, idle scanning, credential
  attacks, exploitation, or persistence;
- importing Nmap source code, NSE scripts, `nmap-service-probes`, `nmap-os-db`,
  or other Nmap-licensed data;
- declaring full cross-platform or full-Nmap feature parity;
- making Nmap mandatory for building, installing, or running Skan;
- tuning only for a benchmark fixture at the expense of general correctness.

## 4. Considered Approaches

### 4.1 Evidence-first vertical slice — selected

Build the comparison and ground-truth system first, close correctness gaps, then
optimize only when the scorecard shows a measurable bottleneck. This creates
credible claims and protects accuracy while performance changes are made.

### 4.2 Feature-first expansion

Merge advanced scan families and scripting before establishing the scorecard.
This increases visible breadth but also increases the unmeasured surface area
and makes regressions harder to attribute. It is deferred.

### 4.3 Throughput-first optimization

Optimize packet emission and concurrency before correctness is measured. This
can produce attractive packets-per-second numbers while increasing false states
under loss or rate limiting. It is rejected for the first milestone.

## 5. Architecture

### 5.1 Package layout

The comparison subsystem lives under `tools/comparison/`:

- `model.py`: immutable scenario, observation, run, metric, and scorecard types;
- `manifest.py`: strict JSON manifest loading and semantic validation;
- `commands.py`: argument-vector construction for Skan and Nmap without shell
  interpolation;
- `parsers.py`: bounded parsers for Skan JSON and Nmap XML;
- `scoring.py`: deterministic confusion matrices, precision, recall, F1, exact
  service matches, and timing summaries;
- `report.py`: stable JSON and Markdown serialization;
- `cli.py`: opt-in orchestration of local authorized comparison runs.

The package uses only the Python standard library. It does not link into the
scanner and cannot affect production scan behavior.

### 5.2 Scenario manifest

The manifest is a versioned JSON document. Every scenario declares:

- a stable identifier;
- an explicit target supplied by the operator;
- protocol and port set;
- expected port state per endpoint;
- optional expected service/product/version evidence;
- a per-run timeout;
- a required `authorization: "operator-controlled-lab"` marker.

The loader rejects unknown schema versions, duplicate identifiers, invalid IP
addresses, invalid ports, empty expectations, unsafe output paths, excessive
scenario counts, and missing authorization markers. The manifest never expands
CIDRs and never discovers targets on its own.

### 5.3 Comparator adapters

Command construction returns argument arrays, never shell command strings. The
runner uses `subprocess.run` with a fixed timeout, captured output, a bounded
environment, and no `shell=True`. Skan emits JSON. Nmap emits XML to standard
output. A comparator absence is reported as `unavailable`, not as a failed or
zero score.

The Nmap adapter is confined to the comparison tool. Production C++ code has no
reference to it.

### 5.4 Normalized evidence

Both parsers produce the same normalized observation model:

- scanner identity and version;
- target address;
- protocol and port;
- state and state reason;
- service, product, version, and confidence when present;
- elapsed time;
- run status and diagnostic.

Unknown fields are ignored only when they are outside the required comparison
contract. Missing required fields invalidate the run. Text and collection sizes
are bounded before allocation or report serialization.

### 5.5 Scoring

Port-state scoring treats ground truth as authoritative and records a full
confusion matrix. In particular, reporting `open` for a non-open endpoint is a
false-open and a release-blocking error.

Service scoring is separated from port-state scoring. It reports:

- exact service identity accuracy;
- product accuracy where ground truth includes a product;
- version accuracy where ground truth includes a version;
- coverage, so a scanner cannot improve apparent accuracy merely by declining
  to identify difficult services.

Timing is compared only when both scanners completed the same scenario and
produced valid results. Reports contain individual samples plus median and p95;
they do not collapse correctness and speed into one opaque score.

## 6. Data Flow

1. The operator prepares an isolated lab and a ground-truth manifest.
2. The CLI validates the entire manifest before launching either scanner.
3. Command adapters generate equivalent bounded scan requests.
4. The runner executes scanners sequentially by default to avoid cross-traffic.
5. Parsers convert structured output into normalized observations.
6. The scorer compares each observation with ground truth.
7. The reporter writes deterministic JSON and Markdown through temporary files
   followed by atomic rename.
8. CI exercises the same pipeline with captured fixtures and no network access.

## 7. Correctness Hardening

Before benchmark results can be authoritative, runtime intelligence loaders must
be bounded. `UDPProbeDatabase` will enforce the existing 1 MiB database ceiling
while reading, reject oversized direct text input and files with `ParseError`,
preserve `NotFound` for absent files, and avoid unbounded `rdbuf()` streaming.

Modern-service fixtures will be introduced test-first. A service identity is
accepted only when the response contains protocol-specific positive evidence.
Generic HTTP, arbitrary JSON keys, or isolated banner fragments must not be
promoted to a product identity.

## 8. Error Handling

- Invalid manifests fail before any process is started.
- Missing scanner binaries produce a typed `unavailable` run.
- Timeouts terminate the child process and produce a typed `timeout` run.
- Non-zero exit codes retain bounded stderr diagnostics and invalidate scoring
  for that scanner/scenario pair.
- Malformed or excessive JSON/XML is rejected without partial scoring.
- A report write failure leaves any previous complete report intact.
- One invalid run does not fabricate comparison values for other runs.

## 9. Verification

All production behavior changes follow RED-GREEN-REFACTOR.

The verification matrix includes:

- unit tests for every model invariant and metric;
- manifest boundary and authorization tests;
- parser fixtures for valid, missing, malformed, duplicate, and oversized data;
- command-construction tests proving there is no shell interpolation;
- deterministic golden JSON and Markdown scorecards;
- UDP database tests for valid, missing, exactly-at-limit, and over-limit input;
- service matcher positive and near-miss negative fixtures;
- the existing registered C++ and Python suites;
- ASan, UBSan, fuzz, corpus, packaging, and GitHub privileged CI gates.

## 10. Superiority Gates

No public superiority claim is permitted until an independently reproducible lab
run satisfies all applicable gates:

1. zero false-open results across the declared comparison suite;
2. port-state accuracy no worse than Nmap for every network-condition class;
3. higher service/version F1 on the declared modern-service suite while
   reporting coverage;
4. at least 20% lower median wall-clock time for the top-1000 TCP LAN profile
   without worsening correctness;
5. no sanitizer, fuzz, unit, integration, packaging, or privileged-CI regression;
6. scorecard contains tool versions, scenario manifest digest, environment
   metadata, raw samples, and reasons for excluded samples.

If the gates are not met, the report states the measured result without a
superiority claim.

## 11. Delivery Sequence

1. Land bounded UDP database loading.
2. Land the offline comparison model, manifest, parsers, and scoring.
3. Land deterministic reports and the opt-in controlled runner.
4. Land modern-service correctness fixtures and matcher repairs.
5. Establish the first versioned scorecard baseline.
6. Use the measured bottlenecks to select the next performance or intelligence
   milestone.
