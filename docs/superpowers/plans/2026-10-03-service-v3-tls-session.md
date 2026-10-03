# TLS session service detection implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Detect TLS and HTTPS using completed sessions and validated decrypted evidence.

**Architecture:** Add an OpenSSL wrapper below the existing TCP transport. Preserve scheduler budgets and corpus bytes; upgrade configured fallbacks after a confirmed TLS handshake. Keep negotiated transport metadata separate from application identity.

**Tech Stack:** C++20, OpenSSL 3.x, epoll, GNU Make, Python standard library.

**Spec:** `docs/superpowers/specs/2026-10-03-service-v3-tls-session-design.md`.

## Global Constraints

- TLS 1.2 through 1.3, HTTP/1.x only; no STARTTLS, HTTP/2 or HTTP/3.
- Certificate chain cap 64 KiB, leaf DER cap 48 KiB, inbound wire cap 512 KiB.
- Preserve the application cap, deadlines, concurrency, retries and cancellation.
- No port/certificate/alert/prefix-derived application identity or software version.
- No plaintext fallback after confirmed TLS; unchanged corpus syntax and bytes.
- Observational certificate metadata, no certificate trust/authenticity claim.
- Push all completed changes; do not force-push or weaken gates.

## Review Focus

- Buffered TLS records must drain without waiting for a new epoll edge.
- Reentrant cancellation and connection creation must preserve callback ownership.
- Failed TLS framing must not finalize close-delimited HTTP or stale identity.
- Handshake/protocol errors and late callbacks must not contaminate another probe.
- All build paths must link/install declared OpenSSL dependencies.

### Task 1: Nonblocking session transport and scheduler integration

**Files:** Create `include/detect/tls_session.hpp`, `src/detect/tls_session.cpp`, `tests/integration/detect/test_service_tls_local.cpp`; modify service probe/scheduler headers and sources, TLS metadata parser and `Makefile`.
**Interfaces:** Produce `TlsSession::handshake()`, `write(std::span<const uint8_t>)`, `read(std::span<uint8_t>)` returning `TlsIoResult`, and `metadata()` returning `TlsMetadata`. Extend `ServiceSubmission` with `tls_session` and `server_name`; extend `ServiceResponse` with `TlsEstablished`/`TlsError` and optional metadata. Preserve existing aggregate field order. Produce `ServiceDetectionConfig::tls_server_name` as an appended field.

- [ ] Add loopback TLS server regression using the existing detector API: self-signed TLS server, two bounded attempts, valid HTTP Server header, expected service `https`, product `nginx`, version `1.26.2`.
- [ ] Run `make build/test_service_tls_local && ./build/test_service_tls_local`. Expected before production change: HTTPS assertion fails after fixture cleanup.
- [ ] Implement OpenSSL state/BIO with exact spec bounds, immediate SSL error interpretation, selected ALPN and bounded leaf DER extraction. Reuse `parse_tls_certificate(std::span<const uint8_t>)` in `tls_metadata.cpp`.
- [ ] Integrate TLS event masks and plaintext delivery into TCP transport; retain cancellation ownership until callbacks unwind.
- [ ] Recognize configured ClientHello probes as handshake-only. On establishment retain generic TLS and run configured fallbacks inside TLS. Map only validated HTTP to HTTPS. Restore earlier candidates when current TLS/application evidence becomes invalid.
- [ ] Add and run TLS 1.2/1.3, IPv4/IPv6, certificate-only, malformed/fragmented HTTP and ALPN tests. Expected: all pass; no fabricated product/version.
- [ ] Run focused service tests and unchanged corpus gate, then commit/push the working transport slice.

### Task 2: Lifecycle, errors, SNI and output evidence

**Files:** TLS loopback tests; service scheduler/probe unit tests; service types sources; output tests as needed.
**Interfaces:** Consume Task 1's typed TLS event and negotiated metadata; produce an explicit `tls-failure` detection error. `tls_server_name` accepts empty or a bounded ASCII DNS name, supplies SNI and the default TLS HTTP Host header.

- [ ] Add negative regressions before corresponding fixes: failed handshake cannot report TLS/HTTPS, abrupt EOF cannot finalize a close-delimited application identity, malformed later chunks revoke identity, byte limit applies to decrypted data, and no plaintext is sent after confirmed TLS.
- [ ] Add callback cancellation/late callback, stalled handshake deadline, multiple concurrent targets, TLS read buffering and write backpressure tests. Expected before fixes: targeted assertion identifies a defect if present.
- [ ] Add SNI/Host positive and invalid-name tests; explicit names must reach the server, certificate names must not supply SNI.
- [ ] Verify JSON/XML/grepable retain negotiated TLS/certificate/selected ALPN and correct service/product/version.
- [ ] Run focused tests, then commit/push verified lifecycle and evidence changes.

### Task 3: Build, documentation and full verification

**Files:** `debian/control`, CI workflows, `tests/packaging/Dockerfile.builder`, build-environment tests, README and `docs/SERVICE_FINGERPRINTS.md`, `docs/SERVICE_TLS_VALIDATION.md`.
**Interfaces:** Consume OpenSSL symbols from Task 1; all executable/fuzz/sanitizer build paths link `-lssl -lcrypto` after objects. Debian declares `libssl-dev (>= 3.0)` and runtime shlibs dependencies.

- [ ] Add build-environment dependency regressions, observe them fail, align declared/toolchain dependencies and verify them pass.
- [ ] Update docs with actual transport behavior, limits, SNI/API/default virtual-host limit, trust semantics, failure behavior and validation results.
- [ ] Run `make -j4 all test test-comparison test-corpus-runtime check-version check-line-endings`, workflow policy/security tests, packaging tests, CLI regressions and deterministic parser replay. Expected: exit 0 with explicit raw-capability skips retained.
- [ ] Run TLS focused tests under GCC ASan/UBSan with halt-on-error. Expected: pass with no sanitizer diagnostic; report any environment-only capability limitation.
- [ ] Commit/push exact verified tree, request one independent whole-branch review, fix Important/Critical findings RED→GREEN and rerun the suite.
- [ ] Open PR, verify exact-head CI, merge the reviewed head and verify remote main/tree and clean local status.
