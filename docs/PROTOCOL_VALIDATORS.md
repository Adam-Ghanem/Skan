# Protocol validators

This change extends the Service V3 HTTP/search/ZooKeeper/MQTT validation boundary
across the installed TCP service families. Baseline: main
`0bba0da172f208782e6745f8244df3b84992a058`. It improves evidence quality; it does
not establish that Skan outperforms another scanner.

## Activation and identity

Validators activate by the resolved rule service family, including a family
expanded from a regex capture. Port hints and probe names never establish an
identity. Renaming a probe cannot bypass the validator. An unrelated request,
UDP response, truncated frame, malformed structure or colliding byte prefix
cannot fall through to a legacy rule for a protected family. Custom families
continue to use bounded legacy matching.

The existing requests are unchanged. These are discovery exchanges, including
the existing anonymous LDAP bind and RouterOS login greeting; this patch adds
no credentials, authentication attempts, new network commands or port scans.

A validated match has structural priority 6 and evidence strength 0.97. This
score describes observed structure, not calibrated probability or peer
identity. A peer can deliberately imitate a protocol or advertise false
metadata. Product versions come from an explicit typed field or a complete
protocol line. Wire-compatible MySQL/MongoDB/PostgreSQL/Redis replies use compatible labels;
CQL negotiation does not claim Apache Cassandra. Protocol versions are recorded separately in
`evidence.protocol_version`; RFB 003.008, SOCKS5, AJP 1.3, NNTP VERSION 2,
rsync 31.0 and SMB dialect 2.0.2 are not software release versions.

## Supported exchanges

| Family | Required evidence | Version source |
|---|---|---|
| MySQL / MariaDB | Complete sequence-zero v10 greeting, version, capabilities and authentication layout | Greeting server version |
| MongoDB | Correlated complete OP_MSG, valid BSON, typed `ok`; CRC32C when present | Direct BSON `version`, only on success |
| Cassandra-compatible | Correlated v4 OPTIONS/SUPPORTED, complete string multimap with CQL_VERSION | No server release inferred |
| SMB2 | Direct TCP frame, NEGOTIATE response, direction, message ID, dialect and security-buffer bounds | Protocol dialect only |
| LDAPv3 | Outstanding anonymous v3 BindRequest, complete BER BindResponse and matching message ID | No OpenLDAP/vendor guess from diagnostics |
| RDP | Complete TPKT/X.224 connection confirmation and optional negotiation response/failure | No software release inferred |
| NFSv3 | Correlated accepted ONC RPC NULL reply and complete verifier/status | Protocol version only |
| DNS over TCP | Complete frame, transaction, QR/opcode, exact question, bounded names/records | None |
| Kerberos | Complete TCP BER KRB-ERROR/AS-REP, mandatory typed outer schema | Protocol version only |
| AMQP | Complete supported protocol header or connection.start frame, typed field table, mechanisms and locales | Explicit RabbitMQ properties only |
| PostgreSQL | Actual SSLRequest and exactly S/N | SSL availability only; not a completed TLS tunnel |
| Minecraft Java | Complete canonical VarInt status frame and typed JSON version/players objects | `version.name` |
| NATS | Complete INFO line and typed JSON server ID, protocol and version | `INFO.version` |
| Redis | Read-only PING/INFO exchange, RESP framing and scoped INFO fields | `INFO.redis_version` |
| SSH | Complete valid 2.0/1.99 identification, bounded preamble and software token | Explicit OpenSSH/Dropbear/libssh token |
| FTP / SMTP | Complete 220 greeting including multiline termination and distinct family/vendor marker | Explicit greeting release |
| POP3 / IMAP | Complete vendor greeting or scoped complete capability response | No release inferred |
| VNC / rsync | Complete permitted RFB banner / numeric RSYNCD greeting | Protocol version only |
| Memcached | Actual version request and complete VERSION line | VERSION token |
| NNTP | Complete 101 capability block, terminating dot and VERSION 2 | Optional explicit INN IMPLEMENTATION |
| SOCKS5 / AJP | Offered-method response / framed CPong | Protocol version only |
| RouterOS API / Telnet | Bounded typed sentence / complete IAC negotiation | No release inferred |
| IRC / TeamSpeak / PJL | Correlated nickname welcome / full query greeting / quoted INFO ID | No release inferred |
| XMPP | Complete stream-opening tag with both exact protocol namespaces and unique quoted attributes | No vendor guessed from namespaces |
| SIP / RTSP | Complete OPTIONS reply, correlated CSeq; SIP Via branch and Call-ID; bounded interim replies | Unique actual Server header |

| HTTP API family | Scoped request and typed identity |
|---|---|
| CouchDB | `/`, welcome and explicit version |
| Prometheus | `/api/v1/status/buildinfo`, successful data object, revision and version |
| Grafana | `/api/health`, database=ok, commit and version |
| Vault | `/v1/sys/health`, documented status codes, boolean health fields, timestamp and version |
| Docker | `/version`, Version plus numeric ApiVersion |
| Kubernetes | `/version`, gitVersion/gitCommit and consistent major/minor |
| etcd | `/version`, explicit server and cluster versions |
| Matrix | `/_matrix/client/versions`, typed current/legacy version list or typed unrecognized-endpoint error; no Synapse guess |
| InfluxDB | `/ping`, successful status and one actual version header |
| Consul | `/v1/status/leader`, JSON string and one valid ACL policy header |
| ClickHouse | Existing SELECT version() path, successful plain numeric three/four-component response |

HTTP APIs require complete HTTP framing and identity content encoding. JSON
rejects duplicate decoded keys, malformed UTF-8, trailing junk, wrong types
and nested identity lookalikes. Vendor headers appearing in the body do not
count. Broad AnyDesk, TeamViewer, router-management and network-management
substring rules now remain unknown; they lack a sufficient scoped protocol
contract.

## Streaming and output

Binary identities wait for the whole first frame. Framed protocols can ignore
coalesced later frames where their contract permits it. SIP validates up to
nine interim/final frames with a shared transaction. RTSP without Content-Length
has zero body and does not wait for connection closure. Redis PONG is soft
while the pipelined INFO frame is pending; a complete INFO frame upgrades the
match. EOF or fallback can retain generic Redis evidence without fabricating
a release. Existing HTTP close-delimited bodies still require orderly EOF.

JSON, XML and grepable output preserve validator ID, completion, version source
and protocol version. Output validation allowlists the family/validator/source
contract and rejects mismatched or invented evidence IDs.

## Bounds and coverage limits

Responses remain limited to 8,192 bytes. JSON/BSON/BER/AMQP nesting is at most
16 levels, with at most 512 parsed nodes where applicable. DNS record counts,
line lengths, property names, capability counts and attribute counts have
additional explicit bounds. Unsupported encodings, compressed Mongo messages,
OP_MSG document sequences, multi-fragment RPC replies and AMQP table dialects
outside the implemented RabbitMQ/Qpid-compatible subset fail closed. Kerberos
validates the outer identity schema and bounded nested BER, not decrypted
cryptographic contents. XMPP validates an opening stream tag, not a complete
XML document. This work does not add TLS session/STARTTLS support, UDP
validators or live-server interoperability coverage.

## Verification

Verified locally on 2026-10-03: production build, full `make test` (213 corpus
and 46 comparison tests plus the registered C++ suite), native protocol replay
and ASan/UBSan validator units/replay passed. The new replay completed
1,014,270 cases; the existing Service V3 replay completed 245,442 cases.
Workflow policy, line endings, version and diff checks passed. No live external
server scan or competitive benchmark was run.

`make test` covers registered C++ tests, corpus migration/runtime tests and
comparison tests. New regressions cover complete positive exchanges, every
prefix truncation of the binary fixtures, wrong requests/transports/IDs,
duplicate keys/headers, invalid types/UTF-8, nested/string collisions,
MariaDB extended capabilities, legacy RDP, ClickHouse four-part releases,
Matrix legacy versions, scheduler fragmentation and output propagation.

`make test-protocol-replay` replays fixture responses, every truncation and
every single-byte substitution against the installed requests in both stream
and terminal modes. The same replay and unit target can run with ASan/UBSan
in a separate BUILD_DIR. This deterministic exercise does not replace
coverage-guided fuzzing. The shared libFuzzer harness now reaches these
validators with valid installed requests instead of fuzzing only malformed
request databases. LeakSanitizer cannot enumerate process threads in this
execution environment, so local ASan/UBSan runs disable leak enumeration.

## Contract references

- [MySQL v10 handshake](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)
- [MariaDB protocol differences](https://mariadb.com/docs/server/reference/clientserver-protocol/mariadb-protocol-differences-with-mysql)
- [MongoDB wire protocol](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/)
- [Cassandra native v4 specification](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec)
- [LDAP RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)
- [ONC RPC RFC 5531](https://www.rfc-editor.org/rfc/rfc5531)
- [Kerberos RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- [AMQP 0-9-1 specification](https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf) and [RabbitMQ table errata](https://www.rabbitmq.com/amqp-0-9-1-errata)
- [SIP RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) and [RTSP 1.0 RFC 2326](https://www.rfc-editor.org/rfc/rfc2326)
- [NATS client protocol](https://docs.nats.io/reference/protocols/client)
- [Prometheus API](https://prometheus.io/docs/prometheus/latest/querying/api/#build-information)
- [Grafana health API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/other/)
- [Vault health API](https://developer.hashicorp.com/vault/api-docs/system/health)
- [Matrix legacy versions](https://spec.matrix.org/legacy/client_server/r0.6.1.html)
