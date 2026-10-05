#include "detect/protocol_evidence.hpp"
#include "detect/service_matcher.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

using namespace skan::detect;
namespace
{
void evidence_contract(const ServiceMatchResult &match)
{
    ServiceResult service;
    service.service = match.service;
    service.version = match.version;
    service.evidence = match.evidence;
    assert(valid_protocol_evidence(service));
}

const ServiceProbeDefinition &probe(const ServiceProbeDatabase &db, std::string_view name)
{
    for (const auto &p : db.probes())
        if (p.name == name)
            return p;
    assert(false);
    return db.probes().front();
}
std::string http(std::string_view body, std::string_view headers = {}, std::string_view status = "200 OK")
{
    return "HTTP/1.1 " + std::string(status) +
           "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n" +
           std::string(headers) + "\r\n" + std::string(body);
}
void rejects_prefix_collisions(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    struct Case
    {
        const char *name;
        std::string bytes;
    };
    const std::vector<Case> cases{
        {"MongoHello", std::string("\0\0\0\0\0\0\0\0NAKS\xdd\x07\0\0", 16)},
        {"MySQLGreeting", std::string("\x0a\0\0\0\x0a"
                                      "8.0.36\0",
                                      12)},
        {"CassandraOptions", std::string("\x84\0\x0a\0\x06\0\0\0\0", 9)},
        {"SMB2Negotiate", std::string("\0\0\0\x66\xfeSMB\x40\0\0\0\0\0\0\0\0\0", 18)},
        {"LDAPBind", std::string("\x30\x0a\x02\x01\x01\x61", 6)},
        {"RDPConnection", std::string("\x03\0\0\x13\x0e\xd0", 6)},
        {"NFS3Null", std::string("\x80\0\0\x28SKNF\0\0\0\x01", 12)},
        {"AMQP091", "AMQP"},
        {"DNSTCP", std::string("\0\x1eSK\x81", 5)},
        {"KerberosASReq", std::string("\0\0\0\x7c\x7e", 5)},
        {"MinecraftStatus", "{\"version\":{\"name\":\"1.21\"},\"players\":{}}"},
        {"RedisInfo", "text redis_version:9.9.9\r\n"},
        {"VNCBanner", "RFB "},
        {"MemcachedVersion", "VERSION 1.6.0"},
        {"MikroTikAPI", "text !done"},
        {"TelnetBanner", std::string("\xff\xfb", 2)},
        {"GenericBanner", "An article about AnyDesk and TeamViewer"},
        {"POP3Capability", "+OK"},
        {"IMAPCapability", "* OK"},
        {"XMPPStream", "text urn:ietf:params:xml:ns:xmpp"}};
    for (const auto &c : cases)
    {
        const auto result = m.match(probe(db, c.name), c.bytes);
        if (result.matched)
            std::cerr << "prefix collision accepted: " << c.name << '\n';
        assert(!result.matched);
    }
}
void api_structures(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    struct Case
    {
        const char *probe;
        const char *service;
        const char *version;
        const char *body;
    };
    const std::vector<Case> cases{
        {"PrometheusBuildInfo", "prometheus", "3.5.0",
         R"({"data":{"revision":"abc123","version":"3.5.0"},"status":"success"})"},
        {"GrafanaHealth", "grafana", "12.2.0", R"({"version":"12.2.0","database":"ok","commit":"abcdef"})"},
        {"VaultHealth", "vault", "1.21.0",
         R"({"version":"1.21.0","server_time_utc":1709559327,"sealed":false,"initialized":true})"},
        {"DockerVersion", "docker", "28.4.0", R"({"ApiVersion":"1.51","Version":"28.4.0"})"},
        {"KubernetesVersion", "kubernetes", "1.34.1",
         R"({"minor":"34","gitCommit":"abcdef","gitVersion":"v1.34.1","major":"1"})"},
        {"EtcdVersion", "etcd", "3.6.4", R"({"etcdcluster":"3.6.0","etcdserver":"3.6.4"})"},
        {"MatrixVersions", "matrix", "", R"({"versions":["v1.1","v1.12"],"unstable_features":{}})"}};
    for (const auto &c : cases)
    {
        const auto &p = probe(db, c.probe);
        const std::string body = c.body, good = http(body);
        auto result = m.match(p, good);
        assert(result.service == c.service && result.version == c.version);
        assert(result.evidence && result.evidence->kind == "structured");
        assert(result.evidence->body_complete);
        evidence_contract(result);
        for (std::size_t n = 0; n < good.size(); ++n)
            assert(m.match(p, std::string_view(good).substr(0, n), false).service != c.service);
        for (const auto &bad : {body + "junk", body.substr(0, body.size() - 1), "{\"nested\":" + body + "}",
                                "{\"text\":" + body + "}"})
        {
            assert(m.match(p, http(bad)).service != c.service);
        }
        auto other = p;
        other.payload = "GET /unrelated HTTP/1.1\r\n\r\n";
        assert(m.match(other, good).service != c.service);
        other = p;
        other.protocol = TransportProtocol::Udp;
        assert(m.match(other, good).service != c.service);
        assert(m.match(p, http(body, "Content-Encoding: gzip\r\n")).service != c.service);
        assert(m.match(p, http(body, {}, "401 Unauthorized")).service != c.service);
        // Duplicate decoded identity keys, header/string lookalikes and wrong types.
    }
    for (const auto bad :
         {R"({"status":"success","data":{"revision":"abc","version":"3.5.0","\u0076ersion":"9.9.9"}})",
          R"({"status":"success","data":{"revision":"abc","version":3.5}})",
          R"({"status":"success","data":{},"revision":"abc","version":"3.5.0"})"})
        assert(m.match(probe(db, "PrometheusBuildInfo"), http(bad)).service != "prometheus");
    assert(m.match(probe(db, "VaultHealth"),
                   http(R"({"initialized":"true","sealed":false,"server_time_utc":1,"version":"1.21.0"})"))
               .service != "vault");
    assert(m.match(probe(db, "KubernetesVersion"),
                   http(R"({"major":"2","minor":"34","gitCommit":"abc","gitVersion":"v1.34.1"})"))
               .service != "kubernetes");
    assert(m.match(probe(db, "MatrixVersions"), http(R"({"versions":[123]})")).service != "matrix");
    assert(m.match(probe(db, "MatrixVersions"), http(R"({"server":{"name":"Synapse"}})")).service !=
           "matrix");

    assert(m.match(probe(db, "ClickHouseVersion"), http("25.8.2.29\n")).version == "25.8.2.29");
    assert(m.match(probe(db, "MatrixVersions"), http(R"({"versions":["r0.6.1","v1.12"]})")).service ==
           "matrix");
    // Vendor headers in a body or duplicate contradictory headers never identify an API.
    const auto &i = probe(db, "InfluxDBPing");
    auto result = m.match(i, "HTTP/1.1 204 No Content\r\nx-influxdb-version: 2.7.12\r\n\r\n");
    assert(result.service == "influxdb" && result.version == "2.7.12");
    assert(m.match(i, http("X-Influxdb-Version: 9.9.9\r\n")).service != "influxdb");
    assert(
        m.match(i,
                "HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 2.7.12\r\nX-Influxdb-Version: 9.9.9\r\n\r\n")
            .service != "influxdb");
    const auto &c = probe(db, "ConsulStatus");
    assert(m.match(c, http("\"10.0.0.1:8300\"", "x-consul-default-acl-policy: allow\r\n")).service ==
           "consul");
    assert(m.match(c, http("\"X-Consul-Default-Acl-Policy: allow\"",
                           "X-Consul-Default-Acl-Policy: allow\r\nX-Consul-Default-Acl-Policy: deny\r\n"))
               .service != "consul");
}
void nats_structure(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    const auto &p = probe(db, "NATSInfo");
    const std::string good = "INFO {\"proto\":1,\"version\":\"2.11.8\",\"server_id\":\"NABC\"}\r\n";
    const auto result = m.match(p, good);
    assert(result.service == "nats" && result.version == "2.11.8" && result.evidence);
    for (std::size_t n = 0; n < good.size(); ++n)
        assert(!m.match(p, std::string_view(good).substr(0, n), false).matched);
    for (const auto bad :
         {"INFO {\"proto\":1,\"version\":\"2.11.8\",\"server_id\":\"NABC\",\"version\":\"9.9.9\"}\r\n",
          "INFO {\"proto\":1,\"version\":\"2.11.8\",\"server_id\":\"NABC\"}junk\r\n",
          "INFO {\"proto\":\"1\",\"version\":\"2.11.8\",\"server_id\":\"NABC\"}\r\n"})
        assert(!m.match(p, bad).matched);
}
void append32(std::string &s, unsigned int n, bool little = true)
{
    for (unsigned int i = 0U; i < 4U; ++i)
        s.push_back(static_cast<char>(n >> (8U * (little ? i : 3U - i))));
}
void put32(std::string &s, std::size_t p, unsigned int n, bool little = true)
{
    for (unsigned int i = 0U; i < 4U; ++i)
        s[p + i] = static_cast<char>(n >> (8U * (little ? i : 3U - i)));
}
std::string ber(unsigned char tag, const std::string &body)
{
    assert(body.size() < 128U);
    return std::string(1U, static_cast<char>(tag)) + std::string(1U, static_cast<char>(body.size())) + body;
}
std::string kerberos_error()
{
    const auto principal = ber(0x30, ber(0xa0, ber(2, std::string(1U, 2))) +
                                         ber(0xa1, ber(0x30, ber(0x1b, "krbtgt") + ber(0x1b, "INVALID"))));
    const auto seq = ber(0xa0, ber(2, std::string(1U, 5))) + ber(0xa1, ber(2, std::string(1U, 30))) +
                     ber(0xa4, ber(0x18, "20261003000000Z")) + ber(0xa5, ber(2, std::string(1U, 0))) +
                     ber(0xa6, ber(2, std::string(1U, 6))) + ber(0xa9, ber(0x1b, "INVALID")) +
                     ber(0xaa, principal);
    const auto body = ber(0x7e, ber(0x30, seq));
    std::string frame;
    append32(frame, static_cast<unsigned int>(body.size()), false);
    return frame + body;
}
void binary_exchanges(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    struct Case
    {
        const char *name;
        const char *service;
        const char *product;
        const char *version;
        std::string response;
    };
    std::string my = "\x0a"
                     "8.0.36";
    my.push_back(0);
    my += std::string(15U, 0);
    std::string mysql;
    append32(mysql, static_cast<unsigned int>(my.size()));
    mysql += my;
    std::string bson;
    append32(bson, 13U);
    bson += std::string("\x10ok\0", 4U);
    append32(bson, 1U);
    bson.push_back(0);
    std::string mongo;
    append32(mongo, 34U);
    append32(mongo, 42U);
    mongo += probe(db, "MongoHello").payload.substr(4U, 4U);
    append32(mongo, 2013U);
    append32(mongo, 0U);
    mongo.push_back(0);
    mongo += bson;
    std::string cassbody = "\0\x01\0\x0b";
    cassbody = std::string("\0\x01\0\x0b", 4U) + "CQL_VERSION" + std::string("\0\x01\0\x05", 4U) + "3.4.5";
    std::string cass = std::string("\x84\0\0\0\x06", 5U);
    append32(cass, static_cast<unsigned int>(cassbody.size()), false);
    cass += cassbody;
    std::string smb(132U, 0);
    put32(smb, 0U, 128U, false);
    smb.replace(4U, 4U, std::string("\xfeSMB", 4U));
    smb[8U] = 64;
    smb[20U] = 1;
    smb.replace(28U, 8U, probe(db, "SMB2Negotiate").payload.substr(28U, 8U));
    smb[68U] = 65;
    smb[72U] = 2;
    smb[73U] = 2;
    std::string rpc;
    append32(rpc, 0x80000018U, false);
    rpc += probe(db, "NFS3Null").payload.substr(4U, 4U);
    for (auto n : {1U, 0U, 0U, 0U, 0U})
        append32(rpc, n, false);
    std::string dns = probe(db, "DNSTCP").payload;
    dns[4U] = static_cast<char>(0x81);
    dns[5U] = static_cast<char>(0x83);
    const std::string mcjson =
        R"({"version":{"name":"1.21.1","protocol":767},"players":{"max":20,"online":0}})";
    assert(mcjson.size() < 125U);
    const std::string mc = std::string(1U, static_cast<char>(mcjson.size() + 2U)) + std::string(1U, 0) +
                           std::string(1U, static_cast<char>(mcjson.size())) + mcjson;
    std::vector<Case> cases{{"KerberosASReq", "kerberos", "Kerberos-v5", "", kerberos_error()},
                            {"MySQLGreeting", "mysql", "MySQL-compatible", "8.0.36", mysql},
                            {"MongoHello", "mongodb", "MongoDB-compatible", "", mongo},
                            {"CassandraOptions", "cassandra", "Cassandra-compatible", "", cass},
                            {"SMB2Negotiate", "microsoft-ds", "SMB2", "", smb},
                            {"LDAPBind", "ldap", "LDAPv3", "",
                             std::string("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\0\x04\0\x04\0", 14U)},
                            {"RDPConnection", "ms-wbt-server", "RDP", "",
                             std::string("\x03\0\0\x13\x0e\xd0\0\0\x12\x34\0\x02\0\x08\0\x01\0\0\0", 19U)},
                            {"NFS3Null", "nfs", "NFS", "", rpc},
                            {"DNSTCP", "dns", "DNS-over-TCP", "", dns},
                            {"AMQP091", "amqp", "AMQP", "", std::string("AMQP\0\0\x09\x01", 8U)},
                            {"MinecraftStatus", "minecraft", "Minecraft-Java", "1.21.1", mc}};
    for (const auto &c : cases)
    {
        const auto &p = probe(db, c.name);
        auto result = m.match(p, c.response);
        if (result.service != c.service)
            std::cerr << "valid exchange rejected: " << c.name << '\n';
        assert(result.service == c.service && result.product == c.product && result.version == c.version &&
               result.evidence);
        evidence_contract(result);
        for (std::size_t n = 0U; n < c.response.size(); ++n)
            assert(!m.match(p, std::string_view(c.response).substr(0U, n), false).matched);
        auto wrong = p;
        wrong.payload = "unrelated";
        assert(!m.match(wrong, c.response).matched);
        wrong = p;
        wrong.protocol = TransportProtocol::Udp;
        assert(!m.match(wrong, c.response).matched);
    }

    std::string maria = "\x0a"
                        "5.5.5-10.11.6-MariaDB";
    maria.push_back(0);
    const auto prefix = maria.size();
    maria += std::string(31U, 0);
    maria[prefix + 27U] = 1;
    std::string mariaframe;
    append32(mariaframe, static_cast<unsigned int>(maria.size()));
    mariaframe += maria;
    assert(m.match(probe(db, "MySQLGreeting"), mariaframe).product == "MariaDB");
    const std::string fakekerb("\0\0\0\x12\x7e\x10\x30\x0e\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\x04\x02hi",
                               22U);
    assert(!m.match(probe(db, "KerberosASReq"), fakekerb).matched);
    const std::string legacyrdp("\x03\0\0\x0b\x06\xd0\0\0\x12\x34\0", 11U);
    assert(m.match(probe(db, "RDPConnection"), legacyrdp).service == "ms-wbt-server");
    auto wrongldap = probe(db, "LDAPBind");
    wrongldap.payload[9U] = 2;
    assert(!m.match(wrongldap, cases[5U].response).matched);
    std::string properties = std::string("\x07productS", 9U);
    append32(properties, 8U, false);
    properties += "RabbitMQ";
    properties += std::string("\x07versionS", 9U);
    append32(properties, 5U, false);
    properties += "4.1.3";
    // AMQP field-table strings use byte lengths, including the whole value.
    std::string start = std::string("\0\x0a\0\x0a\0\x09", 6U);
    append32(start, static_cast<unsigned int>(properties.size()), false);
    start += properties;
    append32(start, 5U, false);
    start += "PLAIN";
    append32(start, 5U, false);
    start += "en_US";
    std::string amqpframe = std::string("\x01\0\0", 3U);
    append32(amqpframe, static_cast<unsigned int>(start.size()), false);
    amqpframe += start;
    amqpframe.push_back(static_cast<char>(0xce));
    assert(m.match(probe(db, "AMQP091"), amqpframe).product == "RabbitMQ");
    for (std::size_t n = 0U; n < amqpframe.size(); ++n)
        assert(!m.match(probe(db, "AMQP091"), std::string_view(amqpframe).substr(0U, n), false).matched);
    auto invalid_utf8 = mongo;
    invalid_utf8[23U] = static_cast<char>(0xff); // BSON key must be UTF-8.
    assert(!m.match(probe(db, "MongoHello"), invalid_utf8).matched);
    auto bad = mongo;
    bad[8U] ^= 1;
    assert(!m.match(probe(db, "MongoHello"), bad).matched);
    bad = cass;
    bad[3U] = 1;
    assert(!m.match(probe(db, "CassandraOptions"), bad).matched);
    bad = smb;
    bad[28U] ^= 1;
    assert(!m.match(probe(db, "SMB2Negotiate"), bad).matched);
    bad = dns;
    bad[2U] ^= 1;
    assert(!m.match(probe(db, "DNSTCP"), bad).matched);
}
void streaming_regressions(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    const auto &rtsp = probe(db, "RTSPOptions");
    assert(m.match(rtsp, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n", false).service ==
           "rtsp");
    const auto headers = "Via: SIP/2.0/TCP scanner.invalid;branch=z9hG4bK-skan\r\nCall-ID: "
                         "skan@scanner.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    const std::string interim = std::string{"SIP/2.0 100 Trying\r\n"} + headers;
    const std::string final = std::string{"SIP/2.0 200 OK\r\n"} + headers;
    assert(!m.match(probe(db, "SIPOptions"), interim, false).matched);
    assert(m.match(probe(db, "SIPOptions"), interim + final, false).service == "sip");
    const auto &redis = probe(db, "RedisInfo");
    assert(m.match(redis, "+PONG\r\n", false).strength == ServiceMatchStrength::Soft);
    const std::string info = "# Server\r\nredis_version:7.2.0\r\n";
    const std::string good = "+PONG\r\n$" + std::to_string(info.size()) + "\r\n" + info + "\r\n";
    assert(m.match(redis, good, false).version == "7.2.0");
    for (std::size_t n = 7U; n < good.size(); ++n)
        assert(m.match(redis, std::string_view{good}.substr(0U, n), false).strength ==
               ServiceMatchStrength::Soft);
}
void text_exchanges(const ServiceProbeDatabase &db)
{
    ServiceMatcher m(db);
    struct Case
    {
        const char *name;
        const char *service;
        const char *response;
    };
    const std::vector<Case> cases{
        {"SSHBanner", "ssh", "SSH-2.0-OpenSSH_9.8\r\n"},
        {"FTPBanner", "ftp", "220 ftp.example vsFTPd 3.0.5 FTP ready\r\n"},
        {"SMTPBanner", "smtp", "220 mail.example ESMTP Postfix\r\n"},
        {"POP3Capability", "pop3", "+OK Dovecot ready.\r\n+OK Capability list\r\nTOP\r\nUIDL\r\n.\r\n"},
        {"IMAPCapability", "imap",
         "* OK Dovecot ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK Done\r\n"},
        {"RedisInfo", "redis", "+PONG\r\n"},
        {"MemcachedVersion", "memcached", "VERSION 1.6.32\r\n"},
        {"VNCBanner", "vnc", "RFB 003.008\n"},
        {"IRCGreeting", "irc", ":irc.example 001 skanprobe :Welcome\r\n"},
        {"TeamSpeakQuery", "teamspeak-query", "TS3\nWelcome to the TeamSpeak 3 ServerQuery interface.\n"},
        {"PJLInfo", "jetdirect", "@PJL INFO ID\r\n\"LaserJet\"\r\n"},
        {"NNTPCapabilities", "nntp", "101 Capability list\r\nVERSION 2\r\nREADER\r\n.\r\n"},
        {"RsyncGreeting", "rsync", "@RSYNCD: 31.0\n"}};
    for (const auto &c : cases)
    {
        const auto &p = probe(db, c.name);
        const auto result = m.match(p, c.response);
        if (result.service != c.service)
            std::cerr << "valid text rejected: " << c.name << '\n';
        assert(result.service == c.service && result.evidence);
        evidence_contract(result);
        auto wrong = p;
        wrong.payload = "unrelated";
        assert(!m.match(wrong, c.response).matched);
    }

    for (const auto &c : std::vector<Case>{
             {"XMPPStream", "xmpp",
              "<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
              "xmlns:stream='http://etherx.jabber.org/streams' id='abc' version='1.0'>"},
             {"SIPOptions", "sip",
              "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP scanner.invalid;branch=z9hG4bK-skan\r\nCall-ID: "
              "skan@scanner.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\nServer: "
              "Asterisk/20.1.0\r\n\r\n"},
             {"RTSPOptions", "rtsp",
              "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\nServer: LIVE555/2026.09.01\r\n\r\n"}})
    {
        const auto &p = probe(db, c.name);
        auto result = m.match(p, c.response);
        assert(result.service == c.service && result.evidence);
        evidence_contract(result);
        auto wrong = p;
        wrong.payload = "unrelated";
        assert(!m.match(wrong, c.response).matched);
    }
    assert(!m.match(probe(db, "XMPPStream"),
                    "<stream:stream xmlns='html' xmlns:stream='http://etherx.jabber.org/streams'>")
                .matched);
    assert(!m.match(probe(db, "RTSPOptions"), "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n").matched);
    assert(!m.match(probe(db, "SIPOptions"), "SIP/2.0 200 OK\r\nCall-ID: other\r\nCSeq: 1 OPTIONS\r\n\r\n")
                .matched);
    assert(m.match(probe(db, "MikroTikAPI"), std::string("\x05!done\0", 7U)).service == "mikrotik-api");
    assert(m.match(probe(db, "TelnetBanner"), std::string("\xff\xfb\x18", 3U)).service == "telnet");
    // Product strings in unrelated response lines cannot supply an identity.
    const auto r = m.match(probe(db, "SMTPBanner"), "220 mail.example ESMTP ready\r\ntext Postfix\r\n");
    assert(r.service == "smtp" && r.product != "Postfix");
    assert(m.match(probe(db, "RedisInfo"), "+PONG\r\ntext redis_version:9.9.9\r\n").version.empty());
    for (const auto bad : {"SSH-2.0-OpenSSH_9.8", "SSH-9.9-OpenSSH_9.8\r\n", "SSH-2.0-\r\n"})
        assert(!m.match(probe(db, "SSHBanner"), bad).matched);
}

} // namespace
int main()
{
    skan::core::StatusCode status{};
    const auto db = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    assert(status == skan::core::StatusCode::Ok);
    rejects_prefix_collisions(db);
    api_structures(db);
    nats_structure(db);
    binary_exchanges(db);
    text_exchanges(db);
    streaming_regressions(db);
    std::cout << "Protocol validator regressions passed\n";
}
