#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "detect/service_matcher.hpp"

namespace {

const skan::detect::ServiceProbeDefinition &probe_named(
    const skan::detect::ServiceProbeDatabase &database, std::string_view name)
{
    for (const auto &probe : database.probes()) {
        if (probe.name == name) return probe;
    }
    assert(false);
    return database.probes().front();
}

void expect(
    const skan::detect::ServiceProbeDatabase &database,
    std::string_view probe_name,
    const std::string &response,
    std::string_view service,
    std::string_view version = {})
{
    const auto &probe = probe_named(database, probe_name);
    const auto match = skan::detect::ServiceMatcher(database).match(probe, response);
    assert(match.matched);
    assert(match.service == service);
    assert(match.version == version);
}

} // namespace

int main()
{
    using namespace skan::detect;
    const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
    assert(database.status() == skan::core::StatusCode::Ok);

    expect(database, "HTTPGet", "HTTP/1.1 200 OK\r\nServer: Caddy/2.8.4\r\n\r\n", "http", "2.8.4");
    expect(database, "SSHBanner", "SSH-2.0-OpenSSH_9.8p1\r\n", "ssh", "9.8p1");
    expect(database, "FTPBanner", "220 ftp.example FTP server ready\r\n", "ftp");
    expect(database, "SMTPBanner", "220 mail.example ESMTP ready\r\n", "smtp");
    expect(database, "POP3Banner", "+OK Dovecot POP3 ready\r\n", "pop3");
    expect(database, "IMAPCapability", "* OK Dovecot IMAP ready\r\n", "imap");
    expect(database, "DNSStatus", std::string{"\x53\x4b\x81\x80", 4U}, "dns");
    expect(database, "RedisPing", "+PONG\r\n", "redis");
    expect(database, "MySQLGreeting", std::string{"\x2a\x00\x00\x00" "8.0.36\x00", 11U}, "mysql", "8.0.36");
    expect(database, "PostgreSQLStartup", "N", "postgresql");
    expect(database, "MongoHello", "reply maxWireVersion value", "mongodb");
    expect(database, "SMBNegotiate", std::string{"\x00\xfeSMB", 5U}, "microsoft-ds");
    expect(database, "RDPConnection", std::string{"\x03\x00\x00\x0b", 4U}, "ms-wbt-server");
    expect(database, "VNCBanner", "RFB 003.008\n", "vnc", "003.008");
    expect(database, "TelnetBanner", std::string{"\xff\xfb\x01", 3U}, "telnet");
    const auto irc = ServiceMatcher(database).match(
        probe_named(database, "IRCGreeting"), ":irc.example 001 skanprobe :welcome\r\n");
    assert(irc.matched && irc.service == "irc" && irc.hostname == "irc.example");

    const auto tls = ServiceMatcher(database).match(
        probe_named(database, "TLSClientHello"), std::string{"\x16\x03\x03\x00\x00", 5U});
    assert(tls.matched && tls.service == "tls" && tls.tunnel == "tls");
    assert(tls.strength == ServiceMatchStrength::Soft);
    assert(tls.tls.detected);
    assert(tls.tls.protocol_version == "TLS 1.2");

    // Unknown banners remain unknown: the corpus never fabricates a product or version.
    const auto unknown = ServiceMatcher(database).match(
        probe_named(database, "GenericBanner"), "opaque binary response");
    assert(!unknown.matched);
    return 0;
}
