#ifndef SKAN_DETECT_PROTOCOL_EVIDENCE_HPP
#define SKAN_DETECT_PROTOCOL_EVIDENCE_HPP

#include "detect/service_types.hpp"
#include <string_view>

namespace skan::detect
{
// Output provenance uses a fixed contract table. Unknown IDs and mismatched families fail
// closed; a protocol version must never substitute for a product version.
inline bool valid_protocol_evidence(const ServiceResult &service) noexcept
{
    struct Contract
    {
        std::string_view family, validator, version_source, protocol_version;
        bool http;
    };
    static constexpr Contract contracts[]{
        {"mysql", "mysql-handshake-v10-v1", "server-version", "10", false},
        {"mongodb", "mongodb-opmsg-bson-v1", "BSON.version", "", false},
        {"cassandra", "cassandra-supported-v4-v1", "", "4", false},
        {"ldap", "ldap-bind-ber-v1", "", "3", false},
        {"ms-wbt-server", "rdp-x224-negotiation-v1", "", "", false},
        {"microsoft-ds", "smb2-negotiate-v1", "", "2.0.2", false},
        {"nfs", "onc-rpc-nfs-null-v1", "", "3", false},
        {"dns", "dns-tcp-message-v1", "", "", false},
        {"kerberos", "kerberos-tcp-ber-v1", "", "5", false},
        {"amqp", "amqp-header-v1", "", "", false},
        {"amqp", "amqp-connection-start-v1", "server-properties.version", "", false},
        {"postgresql", "postgresql-sslresponse-v1", "", "", false},
        {"nats", "nats-info-json-v1", "INFO.version", "", false},
        {"minecraft", "minecraft-status-json-v1", "version.name", "", false},
        {"ssh", "ssh-identification-v1", "software-identification", "*", false},
        {"vnc", "rfb-identification-v1", "", "*", false},
        {"memcached", "memcached-version-v1", "VERSION", "", false},
        {"rsync", "rsync-greeting-v1", "", "*", false},
        {"ftp", "ftp-greeting-v1", "greeting", "", false},
        {"smtp", "smtp-greeting-v1", "greeting", "", false},
        {"pop3", "pop3-capability-v1", "", "", false},
        {"imap", "imap-capability-v1", "", "", false},
        {"nntp", "nntp-capabilities-v1", "IMPLEMENTATION", "2", false},
        {"redis", "redis-resp-v1", "INFO.redis_version", "", false},
        {"irc", "irc-welcome-v1", "", "", false},
        {"teamspeak-query", "teamspeak-query-greeting-v1", "", "", false},
        {"jetdirect", "pjl-info-id-v1", "", "", false},
        {"xmpp", "xmpp-stream-open-v1", "", "", false},
        {"sip", "sip-options-v1", "Server", "2.0", false},
        {"rtsp", "rtsp-options-v1", "Server", "1.0", false},
        {"socks5", "socks5-method-v1", "", "5", false},
        {"ajp13", "ajp13-cpong-v1", "", "1.3", false},
        {"mikrotik-api", "routeros-api-sentence-v1", "", "", false},
        {"telnet", "telnet-negotiation-v1", "", "", false},
        {"couchdb", "couchdb-api-v1", "version", "", true},
        {"clickhouse", "clickhouse-api-v1", "SELECT version()", "", true},
        {"docker", "docker-api-v1", "Version", "", true},
        {"kubernetes", "kubernetes-api-v1", "gitVersion", "", true},
        {"matrix", "matrix-api-v1", "", "", true},
        {"prometheus", "prometheus-api-v1", "data.version", "", true},
        {"grafana", "grafana-api-v1", "version", "", true},
        {"vault", "vault-api-v1", "version", "", true},
        {"etcd", "etcd-api-v1", "etcdserver", "", true},
        {"influxdb", "influxdb-api-v1", "X-Influxdb-Version", "", true},
        {"consul", "consul-api-v1", "", "", true},
    };
    if (!service.evidence)
        return false;
    const auto &e = *service.evidence;
    for (const auto &c : contracts)
    {
        if (e.validator != c.validator)
            continue;
        if (service.service != c.family || e.kind != "structured" || !e.body_complete)
            return false;
        if (service.version.empty())
        {
            if (!e.version_source.empty())
                return false;
        }
        else if (c.version_source.empty() || e.version_source != c.version_source)
            return false;
        if (c.http)
            return e.status_code && (e.protocol_version == "1.0" || e.protocol_version == "1.1");
        return !e.status_code && (c.protocol_version == "*" ? !e.protocol_version.empty()
                                                            : e.protocol_version == c.protocol_version);
    }
    return false;
}
} // namespace skan::detect
#endif
