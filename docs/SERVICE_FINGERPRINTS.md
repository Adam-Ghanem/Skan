# Service fingerprinting

Skan's service/version detector uses the project-owned corpus in `data/service-probes.db`. It is a bounded, clean-room format and is not an Nmap probe database derivative.

## Probe format

```text
Probe TCP HTTPGet rarity=1 priority=100 timeout=1500 ports=80,8080 fallback=GenericBanner
send "GET / HTTP/1.0\r\n\r\n"
match type=regex pattern="^HTTP/([0-9.]+)" service=http product=HTTP version="$1" confidence=0.88
softmatch type=prefix pattern="HTTP/" service=http product=HTTP confidence=0.70
```

`Probe` declares `TCP` or `UDP`, a unique name, rarity, priority, a per-probe timeout in milliseconds, optional port hints, and ordered fallback probe names. The global scan timeout remains a hard ceiling. Payload and pattern strings accept quoted `\r`, `\n`, `\t`, `\\`, `\"`, and `\xNN` escapes.

Hard `match` rules finish detection. `softmatch` rules retain a generic classification while later fallbacks look for stronger evidence. Rules support exact, prefix, suffix, substring, and bounded ECMAScript regex matching. Regex input, pattern length, captures, database size, line size, probes, rules, fallbacks, responses, and extracted TLS names are all capped. Backreferences and common nested-quantifier forms are rejected.

Metadata templates may use regex captures in `service`, `product`, `version`, `extra`, `hostname`, and `tunnel`. A version must only be populated by evidence in the response; generic matches deliberately leave it empty.

## TLS metadata

The TLS probe sends a bounded TLS ClientHello. The detector recognizes TLS records and, when the server exposes unencrypted TLS 1.2 handshake data, extracts the negotiated version, ALPN, leaf certificate subject, issuer, DNS SANs, and raw ASN.1 validity timestamps. TLS 1.3 encrypts certificates after ServerHello, so certificate fields can legitimately be absent. This metadata is observational and does not represent certificate trust verification.

## Corpus coverage

The initial Phase 32 corpus includes deterministic signatures for HTTP, TLS, SSH, FTP, SMTP, POP3, IMAP, DNS, Redis, MySQL, PostgreSQL, MongoDB, SMB, RDP, VNC, Telnet, and IRC. Tests use byte fixtures and loopback only; they never contact public targets.

Use `--service-db <path>` to select another database. Invalid files fail visibly and are never silently replaced by the bundled corpus.
