# Service fingerprinting

Skan's service/version detector uses the project-owned corpus installed at `/usr/share/skan/service-probes.db`; development builds resolve the same repository-owned corpus from `data/service-probes.db` through the centralized runtime path boundary. Resolution never depends on the current working directory. The database is a bounded, clean-room format and is not an Nmap probe database derivative.

## Probe format

```text
Probe TCP HTTPGet rarity=1 priority=100 timeout=1500 ports=80,8080 fallback=GenericBanner
send "GET / HTTP/1.0\r\n\r\n"
match type=regex pattern="^HTTP/([0-9.]+)" service=http product=HTTP version="$1" confidence=0.88
softmatch type=prefix pattern="HTTP/" service=http product=HTTP confidence=0.70
```

`Probe` declares `TCP` or `UDP`, a unique name, rarity, priority, a per-probe timeout in milliseconds, optional port hints, and ordered fallback probe names. Each probe timeout is capped by the service-detection stage timeout; TCP port scanning uses a separate timeout budget so service/version detection does not inherit the connect-scan deadline. Payload and pattern strings accept quoted `\r`, `\n`, `\t`, `\\`, `\"`, and `\xNN` escapes.

Hard `match` rules finish detection. `softmatch` rules retain a generic classification while later fallbacks look for stronger evidence. Soft evidence below `0.60` confidence is not published as a detected service. Across probes, Skan deterministically prefers match strength, publishable evidence, structural match quality, confidence, and specificity; a complete tie retains the earlier scheduled probe. Rules support exact, prefix, suffix, substring, and bounded ECMAScript regex matching. Regex input, pattern length, captures, database size, line size, probes, rules, fallbacks, responses, and extracted TLS names are all capped. Backreferences and common nested-quantifier forms are rejected.

Binary protocol expressions use `[\\s\\S]` for a single arbitrary byte instead
of ECMAScript `.`, because `.` does not match CR or LF bytes. Transaction and
direction evidence must be validated when the protocol exposes it: for example,
the DNS-over-TCP probe requires both Skan's transaction ID and the DNS response
bit, so an echoed query is not accepted. Generic `220` replies and standalone
error codes are not sufficient to distinguish FTP, SMTP, or NNTP; those services
remain unknown unless the response contains protocol-specific evidence.

Every transport response, including close and error notifications, must carry the exact target address from its `ServiceSubmission`. Unattributed or mismatched responses are ignored; the built-in connected TCP and UDP transports provide this attribution.

Metadata templates may use regex captures in `service`, `product`, `version`, `extra`, `hostname`, and `tunnel`. A version must only be populated by evidence in the response; generic matches deliberately leave it empty.

## Validated HTTP, search-root and ZooKeeper evidence

The `http`, `elasticsearch`, `opensearch`, and `zookeeper` families additionally
use bounded protocol validators. A database rule enables its family; for these
families, its legacy regex cannot bypass the validator or manufacture an
identity. Other families retain the existing rule behavior. Runtime databases
and their canonical mirror are unchanged by this engine update.

HTTP accepts complete CRLF-delimited HTTP/1.0 or HTTP/1.1 status and header
blocks. Header names are case-insensitive. Only actual `Server` header fields
can supply HTTP product/version; body text, trailers and informational-response
headers cannot. Duplicate Server fields suppress that identity. A generic
HTTP response has no product/version: the HTTP protocol version appears in
`evidence.protocol_version`, not the product-version field.

Bodies are framed by Content-Length, supported chunked coding, or orderly EOF.
Conflicting lengths, malformed header fields, folded lines and simultaneous
Transfer-Encoding/Content-Length are rejected. Identical repeated decimal
Content-Length fields are accepted; comma-list lengths are deliberately
unsupported. Chunk extensions and trailers are bounded and checked; trailers
cannot redefine framing or representation metadata. Non-identity content
encoding and unsupported transfer-coding chains do not yield parsed body
identity. No decompression, HTTP/2, HTTP/3 or TLS application transport is added.

Elasticsearch/OpenSearch require a correlated TCP `GET / HTTP/1.0` or
`GET / HTTP/1.1`, final status 200, application/json content type and a complete
unencoded body. The JSON parser validates the entire document, including
unused values and UTF-8/Unicode escapes. It rejects duplicate decoded keys,
trailing content, wrong field types, malformed numbers and excess nesting.
Identity requires root string `name`, `cluster_name`, `tagline` and object
`version` with string `number`. Elasticsearch requires its exact official
tagline and no competing distribution marker; OpenSearch requires both its
official tagline and `version.distribution=opensearch`. Version must contain
three numeric components with an optional release/build suffix. Key order is
irrelevant. Nested/string/header lookalikes, auth/error responses and malformed
or truncated JSON preserve only independently valid HTTP/header evidence.

ZooKeeper server identity requires an outstanding TCP `srvr` or `srvr\n`
request and an orderly EOF after a newline-terminated status report. The first
line must carry a valid explicit version; line-scoped mode, latency tuple,
received/sent/connection/outstanding/node counters and hexadecimal zxid are
required. Duplicate/invalid identity fields fail closed. `ruok` retains its
exact `imok` contract, scoped to the actual request. Disabled command replies
remain unknown. No write commands or authentication attempts are introduced.

All responses remain capped at 8,192 bytes. HTTP header blocks are capped at
4,096 bytes and 64 fields; chunks at 256 with 256-byte size/extension lines;
JSON at 16 nested levels, 512 nodes, 128-byte keys and 2,048-byte strings;
ZooKeeper at 64 lines and 1,024 bytes per line. Resource-limit rejection may
reduce coverage; it must not produce a confident product guess.

Validated results expose an additive `evidence` object in JSON, an `evidence`
element in XML and `evidence_*` grepable fields. It records validator ID,
kind (`protocol`, `header`, `structured`, or `legacy-rule`), version source,
HTTP protocol/status when applicable, and body-completion state. The scheduler
retains this metadata across fallback attempts. Streaming callers must pass
`terminal=false` to `ServiceMatcher::match` until orderly EOF; offline callers
default to a complete observation. Socket reset/timeout does not complete a
close-delimited body. Header-only HTTP evidence is provisional soft evidence
while an application body is arriving, so TCP segmentation cannot prematurely
publish an HTTP-only result instead of a search product.

Scores are deterministic heuristics: protocol 0.72, Server header 0.90,
validated search-root/srvr structure 0.97. They are not measured probabilities.
`Server` and application fields are peer assertions, not authenticated product
claims. Broader API fingerprints remain legacy rules and retain their existing
scores. See [validation and limits](SERVICE_V3_VALIDATION.md).

## MQTT framing and evidence

MQTT candidates additionally require the installed clean-session MQTT 3.1.1
CONNECT request and a complete valid CONNACK. Prefix-only, truncated,
reserved-bit and invalid-return-code responses do not identify MQTT.
Other MQTT request profiles are currently unsupported by this validator.
CONNACK identifies no broker product/version, so those fields remain absent;
the requested protocol and, on successful acceptance only, accepted protocol
are exposed separately under `mqtt` in JSON, an `<mqtt>` element in XML, and
`mqtt_*` fields in grepable output. See [the scoped V3 audit and contract](SERVICE_V3_AUDIT.md).

## TLS metadata

The TLS probe sends a bounded TLS ClientHello. The detector recognizes TLS records and, when the server exposes unencrypted TLS 1.2 handshake data, extracts the negotiated version, ALPN, leaf certificate subject, issuer, DNS SANs, and raw ASN.1 validity timestamps. TLS 1.3 encrypts certificates after ServerHello, so certificate fields can legitimately be absent. This metadata is observational and does not represent certificate trust verification.

## Corpus coverage

The bundled project-owned corpus currently covers 47 protocol families: HTTP,
TLS, SSH, FTP, SMTP, POP3, IMAP, Redis, MySQL, PostgreSQL, MongoDB, Memcached,
Cassandra, ClickHouse, Docker, Kubernetes, Matrix, SMB, LDAP, RDP, VNC, NFS,
AMQP, MQTT, IRC, XMPP, SIP, RTSP, Minecraft, TeamSpeak, Telnet, PJL, MikroTik
API, DNS, Kerberos, NNTP, SOCKS5, AJP13, rsyncd, Prometheus, Grafana, and a
Vault-compatible health API, NATS, etcd, InfluxDB, Consul, and ZooKeeper.
Standards-backed probes
use read-only or negotiation-only messages: NNTP `CAPABILITIES`
([RFC 3977](https://www.rfc-editor.org/rfc/rfc3977)), SOCKS5 method selection
([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)), AJP13 `CPing`
([Apache Tomcat AJP reference](https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html)),
and the [upstream rsync project](https://rsync.samba.org/) daemon greeting.

The current expansion batch was authored clean-room from protocol facts in those primary references; no Nmap or third-party fingerprint database text was imported. The auditable derivation boundary is:

| Probe | Primary fact used | Skan-authored evidence rule |
| --- | --- | --- |
| `NNTPCapabilities` | RFC 3977 reply codes and `CAPABILITIES`/`VERSION` lines | bounded status, version, and INN implementation expressions |
| `SOCKS5Greeting` | RFC 1928 version-5 method negotiation octets | exact replies for the offered no-auth method or no acceptable method |
| `AJP13CPing` | Apache AJP13 packet magic and CPing/CPong types | exact five-byte CPong frame only |
| `RsyncGreeting` | upstream daemon greeting prefix and numeric protocol version | line-terminated version expression plus non-final soft prefix |
| `PrometheusBuildInfo` | [Prometheus build-information API](https://prometheus.io/docs/prometheus/latest/querying/api/#build-information) success envelope and string build fields | HTTP-anchored success, version, and revision evidence |
| `GrafanaHealth` | [Grafana Health API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/other/#health-api) commit, database, and version response | HTTP-anchored three-field health tuple with captured version |
| `VaultHealth` | [Vault system health API](https://developer.hashicorp.com/vault/api-docs/system/health) status codes and health response fields | documented status plus initialized, sealed, server-time, and version evidence; vendor-neutral `Vault-API` product label |
| `NATSInfo` | [NATS client protocol](https://docs.nats.io/reference/reference-protocols/nats-protocol) server-first `INFO` operation and JSON fields | anchored `INFO` frame requiring server identity and protocol fields before publishing the explicit version |
| `EtcdVersion` | [etcd version endpoint](https://etcd.io/docs/v2.3/api/#getting-the-etcd-version) server and cluster version fields | HTTP-anchored two-field document that publishes only the explicit server version |
| `InfluxDBPing` | [InfluxDB ping API](https://docs.influxdata.com/influxdb/v2/api/ping/) availability status and version header | HTTP-anchored 200/204 response with a case-tolerant `X-Influxdb-Version` header |
| `ConsulStatus` | [Consul status API](https://developer.hashicorp.com/consul/api-docs/status) and [default ACL response header](https://developer.hashicorp.com/consul/api-docs/api-structure#default-acl-policy) | read-only leader request plus HTTP-anchored vendor header; no version is invented |
| `ZooKeeperRuok` | [ZooKeeper four-letter commands](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_zkCommands) | exact `imok` response to the side-effect-free `ruok` health command |

Cloud-native fallback signatures are also collision-tested. Standalone strings
such as `gitVersion`, `Docker-Experimental`, `X-ClickHouse-`,
`M_UNRECOGNIZED`, or `Synapse` do not identify a service without an HTTP
status line and the protocol-specific response structure expected by the
probe.

`make test-service-corpus` loads the installed-format runtime database with the production C++ parser and evaluates the bounded offline cases in `tests/data/service-fingerprints-v1.tsv`. Cases include expected service, product, version, confidence, and collision-negative responses. The fixture format is deliberately simple, deterministic, and capped at 4,096 cases so coverage can grow without introducing a second matcher implementation. Tests use synthetic byte fixtures and loopback only; they never contact public targets.

Use `--service-db <path>` to select another database. An explicit path takes precedence over installed and development defaults. Invalid files fail visibly and are never silently replaced by the bundled corpus.

## Intelligence Database v2 staging

The runtime file above remains authoritative. Schema-v2 source governance and
canonical staging are documented in [Intelligence Database v2](INTELLIGENCE_DATABASE.md).
Skan will not switch to generated runtime databases until the migration compiler
proves semantic round trips through the real C++ loaders.
