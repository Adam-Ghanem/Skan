# TLS session validation

Skan negotiates TLS 1.2–1.3 with OpenSSL 3 through its existing nonblocking TCP transport. The project-owned corpus is unchanged. A completed handshake establishes generic TLS; validated decrypted application evidence supplies product/version. This is inventory, without certificate chain or hostname trust verification.

## Reproduce

On Linux with a C++20 compiler, Make and OpenSSL 3 development libraries:

```sh
make -j4 build/test_service_tls_local build/test_service_tls_scheduler
./build/test_service_tls_local
./build/test_service_tls_scheduler
make -j4 all test test-comparison test-corpus-runtime check-version check-line-endings
python3 -m unittest discover -s tests/packaging -p 'test_*.py'
python3 -m unittest discover -s tests/security -p 'test_*.py'
python3 scripts/validate_workflow_policy.py .github/workflows/*.yml
bash tests/integration/cli/test_nmap_compat.sh
```

The local TLS fixture generates an ephemeral self-signed EC certificate and binds only loopback. IPv6 unavailability is an explicit skip. Raw scanner/interface capability checks retain their existing explicit skips; CI's isolated privileged lab validates raw IPv4/IPv6 behavior independently.

## Regression evidence

| Fixture | Required result |
| --- | --- |
| TLS 1.2/1.3 over IPv4/IPv6; HTTP split across records | HTTPS, nginx 1.26.2, negotiated version, selected http/1.1 |
| Certificate-only handshake with product/version-like CN | Generic TLS, certificate metadata, empty software identity |
| Malformed chunk framing or abrupt EOF | Retained TLS only; no incomplete application identity |
| 6 KiB body buffered inside a TLS record | Complete HTTP evidence; drain without another socket edge |
| Plaintext response to a TLS handshake | TLS_FAILURE, no TLS identity |
| Stalled handshake | Existing deadline expires, no fabricated identity |
| Decrypted response beyond the configured cap | RESPONSE_TOO_LARGE, retained transport metadata only |
| Two simultaneous targets with different versions | Target/port attribution and independent TLS/application evidence |
| Callback cancels current connection and submits another | One handshake per attempt; no late delivery after cancellation |
| Socketpair with forced write backpressure | WANT_WRITE retry preserves exact payload; wrapper does not close borrowed descriptor |
| Explicit valid DNS name | Server observes SNI and matching default HTTP Host |
| Invalid DNS, CR/LF, NUL, IP or oversized name | Rejected before transport submission |
| No explicit DNS name or no selected ALPN | SNI/ALPN absent; certificate names/offered ALPN do not populate them |
| Duplicate/wrong-target/late handshake events | Ignored without replacing current or previous evidence |
| Real HTTPS result through JSON/XML/grepable | Application fields, negotiated TLS, certificate and selected ALPN preserved |

All listed focused regressions passed locally. Final branch verification on 2026-10-03 passed:

- Full registered native suite, 213 corpus tests, 46 comparison tests, generated-runtime-loader gate, version and line-ending checks.
- 14 packaging Python tests, 8 security/workflow tests, workflow policy validation, 10 CLI Python tests, Nmap-compatible CLI shell regression and staged `make install` checks.
- Both TLS focused binaries under combined GCC ASan/UBSan with halt-on-error and no diagnostic, including reentrant cancellation and forced write backpressure. Local leak detection was disabled because of the execution environment; CI retains its full ASan/LSan gate.
- 245,442 deterministic parser replays under ASan/UBSan, covering every seed prefix and one-byte mutation. This is regression replay; CI separately retains coverage-guided fuzzing.

Remote build, sanitizer, fuzz, corpus, package and isolated privileged-lab gates must pass on the exact reviewed PR head before merge.

## Limits

The client offers only HTTP/1.1 ALPN; HTTP/2, HTTP/3 and STARTTLS are unsupported. The CLI currently has no SNI option and IP-only scans observe a server's default virtual host. Library callers can supply `tls_server_name`, without enabling certificate trust verification. Generic TLS carries no software version. See [the transport and evidence contract](SERVICE_FINGERPRINTS.md#tls-metadata).
