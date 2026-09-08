# HTTP Fallback After Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve bounded service detection when a protocol-specific TCP probe is reset by an already-open service, allowing the next configured probe to identify the service.

**Architecture:** Keep the existing single `ServiceScheduler` and transport pipeline. Treat a connection reset from one active service-detection probe as probe-local evidence when another bounded probe remains, advance through the existing `probe_indices`, and preserve terminal behavior when no fallback remains. Do not infer service from port number and do not increase `max_probes_per_port`.

**Tech Stack:** C++20, existing `ServiceScheduler`, `RecordingServiceTransport`, project Makefile/unit tests, GitHub Actions.

**Spec:** GitHub Issue #28 (`Fix HTTP detection after failed TLS probe on TCP/443`).

## Global Constraints

- Do not hardcode `443=http` or any service from a port number.
- Keep the existing single-reactor/service-scheduler architecture.
- Do not add a second scheduler, polling loop, sleep loop, or fallback transport.
- Keep `ServiceDetectionConfig::max_probes_per_port` unchanged.
- Preserve existing timeout, response-size, soft-match, and bounded-probe semantics.
- Public-host behavior is diagnostic only; acceptance is deterministic through `RecordingServiceTransport`.

---

### Task 1: Prove and fix reset-to-fallback behavior

**Files:**
- Modify: `tests/unit/detect/test_service_scheduler.cpp`
- Modify only if RED confirms the hypothesis: `src/detect/service_scheduler.cpp`

**Interfaces:**
- Consumes: `ServiceScheduler::submit`, `ServiceScheduler::receive`, `ServiceResponseKind::SocketError`, `ServiceDetectionConfig`, and `RecordingServiceTransport::deliver`.
- Produces: existing scheduler behavior where a reset (`ECONNRESET`) on one probe advances to the next configured probe when one remains; no public API changes.

- [ ] **Step 1: Write the failing regression test**

Add a deterministic database with a port-443 `TLSClientHello` probe that falls back to `HTTPGet`. Submit an open TCP/443 result, deliver `ServiceResponseKind::SocketError` with `ECONNRESET` for the TLS probe, assert that `HTTPGet` is submitted, then deliver `HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n\r\n` and assert `service == "http"`, `product == "Apache"`, and `version == "2.4.29"`.

Also assert before any response that the first submission is `TLSClientHello`; this proves the test exercises protocol ordering rather than a port-number shortcut.

- [ ] **Step 2: Verify RED**

Run the repository's registered unit/CI test suite on the test-only commit. Expected failure: after `ECONNRESET`, only one submission exists or the scheduler has already produced an error result instead of scheduling `HTTPGet`.

If the test passes on unchanged production code, stop: the reset hypothesis is false and no production change is allowed under TDD. Update Issue #28 with the evidence and continue root-cause investigation.

- [ ] **Step 3: Implement the minimal scheduler fix**

Only after RED, change the `ServiceScheduler::receive` handling for a TCP `SocketError` carrying `ECONNRESET` so that, when another probe exists, the current pending attempt is cancelled/removed and its `WorkItem` is requeued with `next_probe` advanced by one. Preserve the existing final error result when no further probe exists. Do not change handling for invalid targets, response-too-large conditions, or unrelated transport failures.

- [ ] **Step 4: Verify GREEN**

Run the focused service-scheduler test plus the full registered test suite. Expected: the new reset regression passes and all existing tests remain green.

- [ ] **Step 5: Review and open PR**

Confirm the diff contains only the regression test, the minimal scheduler change (if RED required it), and this plan. Open a PR referencing Issue #28 and require CI before merge.
