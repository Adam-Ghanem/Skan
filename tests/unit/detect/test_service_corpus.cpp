#include <cassert>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "detect/service_matcher.hpp"

namespace {

constexpr std::size_t kMaximumFixtureBytes = 1U << 20U;
constexpr std::size_t kMaximumFixtureLineBytes = 8U << 10U;
constexpr std::size_t kMaximumFixtureCases = 4096U;
constexpr std::size_t kFixtureFieldCount = 8U;

struct FingerprintCase final {
    std::string id;
    bool should_match{false};
    std::string probe;
    std::string response;
    std::string service;
    std::string product;
    std::string version;
    double minimum_confidence{0.0};
};

bool safe_identifier(std::string_view value)
{
    if (value.empty() || value.size() > 128U) return false;
    for (const char character : value) {
        const bool valid = (character >= 'a' && character <= 'z') ||
                           (character >= '0' && character <= '9') ||
                           character == '-' || character == '_' || character == '.';
        if (!valid) return false;
    }
    return true;
}

std::vector<std::string_view> split_fields(const std::string &line)
{
    std::vector<std::string_view> fields;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const std::size_t separator = line.find('\t', start);
        fields.emplace_back(
            line.data() + start,
            separator == std::string::npos ? line.size() - start : separator - start);
        if (separator == std::string::npos) break;
        start = separator + 1U;
    }
    return fields;
}

unsigned int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned int>(value - 'a') + 10U;
    throw std::runtime_error("fixture response must use lowercase hexadecimal");
}

std::string decode_hex(std::string_view value)
{
    if (value.empty() || value.size() % 2U != 0U || value.size() > 16384U) {
        throw std::runtime_error("fixture response has invalid hexadecimal length");
    }
    std::string decoded;
    decoded.reserve(value.size() / 2U);
    for (std::size_t index = 0U; index < value.size(); index += 2U) {
        const unsigned int byte = (hex_nibble(value[index]) << 4U) | hex_nibble(value[index + 1U]);
        decoded.push_back(static_cast<char>(byte));
    }
    return decoded;
}

std::string optional_field(std::string_view value)
{
    if (value == "-") return {};
    if (value.empty() || value.size() > 256U) {
        throw std::runtime_error("fixture expectation is invalid");
    }
    return std::string{value};
}

double parse_confidence(std::string_view value)
{
    double confidence = 0.0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), confidence);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        !std::isfinite(confidence) ||
        confidence < 0.0 || confidence > 1.0) {
        throw std::runtime_error("fixture confidence is invalid");
    }
    return confidence;
}

std::vector<FingerprintCase> parse_cases(std::istream &stream)
{
    std::vector<FingerprintCase> cases;
    std::unordered_set<std::string> identifiers;
    std::string line;
    std::size_t bytes_read = 0U;
    while (std::getline(stream, line)) {
        bytes_read += line.size() + 1U;
        if (bytes_read > kMaximumFixtureBytes || line.size() > kMaximumFixtureLineBytes) {
            throw std::runtime_error("fixture corpus exceeds its size boundary");
        }
        if (!line.empty() && line.back() == '\r') {
            throw std::runtime_error("fixture corpus must use LF line endings");
        }
        if (!line.empty() && line.front() == '#') continue;
        if (line.empty()) throw std::runtime_error("fixture corpus contains a blank line");
        const std::vector<std::string_view> fields = split_fields(line);
        if (fields.size() != kFixtureFieldCount || !safe_identifier(fields[0])) {
            throw std::runtime_error("fixture record shape is invalid");
        }
        FingerprintCase test_case;
        test_case.id = fields[0];
        if (!identifiers.emplace(test_case.id).second) {
            throw std::runtime_error("fixture case identifier is duplicated");
        }
        if (fields[1] == "match") {
            test_case.should_match = true;
        } else if (fields[1] != "none") {
            throw std::runtime_error("fixture outcome is invalid");
        }
        if (fields[2].empty() || fields[2].size() > 128U) {
            throw std::runtime_error("fixture probe name is invalid");
        }
        test_case.probe = fields[2];
        test_case.response = decode_hex(fields[3]);
        test_case.service = optional_field(fields[4]);
        test_case.product = optional_field(fields[5]);
        test_case.version = optional_field(fields[6]);
        test_case.minimum_confidence = parse_confidence(fields[7]);
        if ((!test_case.should_match &&
             (!test_case.service.empty() || !test_case.product.empty() || !test_case.version.empty() ||
              test_case.minimum_confidence != 0.0)) ||
            (test_case.should_match && test_case.service.empty())) {
            throw std::runtime_error("fixture expectations conflict with outcome");
        }
        cases.push_back(std::move(test_case));
        if (cases.size() > kMaximumFixtureCases) {
            throw std::runtime_error("fixture case count exceeds its boundary");
        }
    }
    if (!stream.eof() || cases.empty()) throw std::runtime_error("fixture corpus is incomplete");
    return cases;
}

const skan::detect::ServiceProbeDefinition &probe_named(
    const skan::detect::ServiceProbeDatabase &database, std::string_view name)
{
    for (const auto &probe : database.probes()) {
        if (probe.name == name) return probe;
    }
    throw std::runtime_error("service probe not found: " + std::string{name});
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
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    assert(status == skan::core::StatusCode::Ok);

    {
        bool rejected = false;
        try {
            (void)probe_named(database, "ProbeThatDoesNotExist");
        } catch (const std::runtime_error &) {
            rejected = true;
        }
        if (!rejected) {
            std::cerr << "missing service probe was not rejected\n";
            return 1;
        }
    }

    expect(database, "HTTPGet", "HTTP/1.1 200 OK\r\nServer: Caddy/2.8.4\r\n\r\n", "http", "2.8.4");
    expect(database, "SSHBanner", "SSH-2.0-OpenSSH_9.8p1\r\n", "ssh", "9.8p1");
    expect(
        database,
        "SSHBanner",
        "Authorized access only\r\nSSH-2.0-OpenSSH_9.8p1\r\n",
        "ssh",
        "9.8p1");
    expect(
        database,
        "SSHBanner",
        "NOTICE: monitored system\nUnauthorized use prohibited\r\nSSH-2.0-OpenSSH_8.9p1\r\n",
        "ssh",
        "8.9p1");
    expect(
        database,
        "GenericBanner",
        "Legal notice\r\nSSH-2.0-OpenSSH_9.7p1\r\n",
        "ssh",
        "9.7p1");
    const auto missing_ssh_identification = ServiceMatcher(database).match(
        probe_named(database, "SSHBanner"),
        "Authorized access only\r\nNo protocol identification follows\r\n");
    assert(!missing_ssh_identification.matched);

    expect(database, "FTPBanner", "220 ftp.example FTP server ready\r\n", "ftp");
    expect(database, "SMTPBanner", "220 mail.example ESMTP ready\r\n", "smtp");
    expect(database, "POP3Capability", "+OK Dovecot POP3 ready\r\n", "pop3");
    expect(database, "IMAPCapability", "* OK Dovecot IMAP ready\r\n", "imap");
    auto dns = probe_named(database, "DNSTCP").payload;
    dns[4U] = static_cast<char>(0x81); dns[5U] = static_cast<char>(0x83);
    expect(database, "DNSTCP", dns, "dns");
    expect(database, "RedisInfo", "+PONG\r\n", "redis");
    const std::string info = "# Server\r\nredis_version:7.4.1\r\n";
    expect(database, "RedisInfo", "+PONG\r\n$" + std::to_string(info.size()) + "\r\n" + info + "\r\n", "redis", "7.4.1");
    expect(database, "PostgreSQLSSLRequest", "N", "postgresql");
    expect(database, "VNCBanner", "RFB 003.008\n", "vnc");
    expect(database, "TelnetBanner", std::string{"\xff\xfb\x01", 3U}, "telnet");
    expect(database, "MemcachedVersion", "VERSION 1.6.32\r\n", "memcached", "1.6.32");
    expect(database, "MQTTConnect", std::string{"\x20\x02\x00\x00", 4U}, "mqtt", "");
    expect(database, "AMQP091", std::string{"AMQP\x00\x00\x09\x01", 8U}, "amqp");

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

    const std::filesystem::path fixture_path{"tests/data/service-fingerprints-v1.tsv"};
    assert(std::filesystem::file_size(fixture_path) <= kMaximumFixtureBytes);
    std::ifstream fixture_stream(fixture_path, std::ios::binary);
    assert(fixture_stream.is_open());
    const std::vector<FingerprintCase> cases = parse_cases(fixture_stream);
    for (const FingerprintCase &test_case : cases) {
        const ServiceMatchResult match = ServiceMatcher(database).match(
            probe_named(database, test_case.probe), test_case.response);
        if (!test_case.should_match) {
            if (match.matched) {
                std::cerr << "unexpected fingerprint match: " << test_case.id << '\n';
                return 1;
            }
            continue;
        }
        if (!match.matched || match.service != test_case.service ||
            match.product != test_case.product || match.version != test_case.version ||
            match.confidence < test_case.minimum_confidence) {
            std::cerr << "fingerprint case failed: " << test_case.id
                      << " service=" << match.service
                      << " product=" << match.product
                      << " version=" << match.version
                      << " confidence=" << match.confidence << '\n';
            return 1;
        }
    }

    {
        std::istringstream invalid{
            "bad\tmatch\tProbe\t0G\tservice\t-\t-\t0.90\n"};
        bool rejected = false;
        try {
            (void)parse_cases(invalid);
        } catch (const std::runtime_error &) {
            rejected = true;
        }
        assert(rejected);
    }
    {
        std::istringstream invalid{
            "non-finite-confidence\tmatch\tProbe\t00\tservice\t-\t-\tnan\n"};
        bool rejected = false;
        try {
            (void)parse_cases(invalid);
        } catch (const std::runtime_error &) {
            rejected = true;
        }
        if (!rejected) {
            std::cerr << "non-finite fixture confidence was not rejected\n";
            return 1;
        }
    }
    return 0;
}
