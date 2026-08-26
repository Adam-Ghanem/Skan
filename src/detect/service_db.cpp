#include "detect/service_db.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <fstream>
#include <new>
#include <sstream>
#include <system_error>

namespace skan::detect {
namespace {

constexpr std::size_t kMaximumDatabaseBytes = 1U << 20U;
constexpr std::size_t kMaximumLineBytes = 16U << 10U;
constexpr std::size_t kMaximumProbeCount = 256U;
constexpr std::size_t kMaximumRulesPerProbe = 256U;
constexpr std::size_t kMaximumPatternBytes = 4096U;

constexpr std::string_view kBuiltInDatabase = R"DB(
# Skan-owned compact service probe database. This is not the Nmap database.
Probe TCP HTTPGet rarity=1 ports=80,8000,8080
send "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
match type=regex pattern="^[Hh][Tt][Tt][Pp]/([0-9.]+)" service=http product=HTTP version="$1" confidence=0.82
match type=regex pattern="^[Ss]erver: ([A-Za-z0-9._-]+)/([0-9.]+)" service=http product="$1" version="$2" confidence=0.88
match type=prefix pattern="HTTP/" service=http product=HTTP confidence=0.72

Probe TCP SSHBanner rarity=1 ports=22
send "\r\n"
match type=regex pattern="^SSH-[0-9.]+-OpenSSH_([0-9.]+)" service=ssh product=OpenSSH version="$1" confidence=0.92

Probe TCP FTPBanner rarity=1 ports=21
send "\r\n"
match type=prefix pattern="220" service=ftp product=FTP confidence=0.80

Probe TCP SMTPBanner rarity=1 ports=25,587
send "\r\n"
match type=prefix pattern="220" service=smtp product=SMTP confidence=0.80

Probe TCP TLSGreeting rarity=1 ports=443,8443
send "\x16\x03\x01\x00\x00"
match type=prefix pattern="\x16\x03" service=https product=TLS version="record-header" confidence=0.76
match type=exact pattern="\x15\x03" service=tls product=TLS version="alert" confidence=0.82

Probe TCP POP3Banner rarity=2 ports=110,995
send "\r\n"
match type=prefix pattern="+OK" service=pop3 product=POP3 confidence=0.80

Probe TCP IMAPBanner rarity=2 ports=143,993
send "a001 CAPABILITY\r\n"
match type=prefix pattern="* OK" service=imap product=IMAP confidence=0.82

Probe TCP RedisGreeting rarity=2 ports=6379
send "PING\r\n"
match type=prefix pattern="+PONG" service=redis product=Redis confidence=0.86

Probe TCP MongoGreeting rarity=2 ports=27017
send "\x00"
match type=prefix pattern="\x00" service=mongodb product=MongoDB confidence=0.40

Probe TCP GenericBanner rarity=3
send "\r\n"
match type=regex pattern="^SSH-[0-9.]+-OpenSSH_([0-9.]+)" service=ssh product=OpenSSH version="$1" confidence=0.75
match type=regex pattern="^[Hh][Tt][Tt][Pp]/([0-9.]+)" service=http product=HTTP version="$1" confidence=0.74
match type=prefix pattern="SSH-" service=ssh product=SSH confidence=0.60
match type=prefix pattern="220" service=banner product=TextBanner confidence=0.45
match type=prefix pattern="HTTP/" service=http product=HTTP confidence=0.60

Probe UDP DNSQuery rarity=1 ports=53
send "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
match type=prefix pattern="\x12\x34" service=dns product=DNS confidence=0.82

Probe UDP NTPQuery rarity=2 ports=123
send "\x1b\x00\x00\x00\x00\x00\x00\x00"
match type=prefix pattern="\x1c" service=ntp product=NTP confidence=0.72

Probe UDP SNMPQuery rarity=2 ports=161
send "\x30"
match type=prefix pattern="\x30" service=snmp product=SNMP confidence=0.75

Probe UDP SSDPQuery rarity=2 ports=1900
send "M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\n\r\n"
match type=prefix pattern="HTTP/1.1" service=ssdp product=UPnP confidence=0.78
)DB";

std::string_view trim(std::string_view value) noexcept
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1U);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1U);
    }
    return value;
}

std::string_view without_comment(std::string_view value) noexcept
{
    bool quoted = false;
    bool escaped = false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        const char character = value[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && character == '\\') {
            escaped = true;
            continue;
        }
        if (character == '"') {
            quoted = !quoted;
        } else if (!quoted && character == '#') {
            return value.substr(0U, index);
        }
    }
    return value;
}

bool decode_escape(char escaped, char &decoded) noexcept
{
    switch (escaped) {
    case 'r':
        decoded = '\r';
        return true;
    case 'n':
        decoded = '\n';
        return true;
    case 't':
        decoded = '\t';
        return true;
    case '\\':
        decoded = '\\';
        return true;
    case '"':
        decoded = '"';
        return true;
    default:
        return false;
    }
}

bool tokenize(std::string_view line, std::vector<std::string> &tokens)
{
    tokens.clear();
    std::size_t index = 0U;
    while (index < line.size()) {
        while (index < line.size() && std::isspace(static_cast<unsigned char>(line[index])) != 0) {
            ++index;
        }
        if (index == line.size()) {
            break;
        }
        std::string token;
        bool quoted = false;
        bool closed = true;
        while (index < line.size()) {
            const char character = line[index++];
            if (character == '"') {
                quoted = !quoted;
                closed = !quoted;
                continue;
            }
            if (character == '\\') {
                if (index == line.size()) {
                    return false;
                }
                const char escaped = line[index++];
                if (escaped == 'x' && index + 1U < line.size()) {
                    const auto hex = [](char value) noexcept -> int {
                        if (value >= '0' && value <= '9') {
                            return value - '0';
                        }
                        if (value >= 'a' && value <= 'f') {
                            return value - 'a' + 10;
                        }
                        if (value >= 'A' && value <= 'F') {
                            return value - 'A' + 10;
                        }
                        return -1;
                    };
                    const int high = hex(line[index]);
                    const int low = hex(line[index + 1U]);
                    if (high < 0 || low < 0) {
                        token.push_back('\\');
                        token.push_back(escaped);
                    } else {
                        token.push_back(static_cast<char>((high << 4) | low));
                        index += 2U;
                    }
                } else {
                    char decoded = '\0';
                    if (decode_escape(escaped, decoded)) {
                        token.push_back(decoded);
                    } else {
                        token.push_back('\\');
                        token.push_back(escaped);
                    }
                }
            } else if (!quoted && std::isspace(static_cast<unsigned char>(character)) != 0) {
                break;
            } else {
                token.push_back(character);
            }
        }
        if (quoted || !closed) {
            return false;
        }
        tokens.push_back(std::move(token));
    }
    return true;
}

bool split_assignment(std::string_view token, std::string_view &key, std::string_view &value) noexcept
{
    const std::size_t equal = token.find('=');
    if (equal == std::string_view::npos || equal == 0U) {
        return false;
    }
    key = token.substr(0U, equal);
    value = token.substr(equal + 1U);
    return !value.empty();
}

bool parse_unsigned(std::string_view value, unsigned int &output) noexcept
{
    if (value.empty()) {
        return false;
    }
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output, 10);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
}

bool parse_confidence(std::string_view value, double &output) noexcept
{
    if (value.empty()) {
        return false;
    }
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && output >= 0.0 &&
           output <= 1.0;
}

bool parse_match_type(std::string_view value, ServiceMatchType &type) noexcept
{
    if (value == "exact") {
        type = ServiceMatchType::Exact;
    } else if (value == "prefix") {
        type = ServiceMatchType::Prefix;
    } else if (value == "substring") {
        type = ServiceMatchType::Substring;
    } else if (value == "regex") {
        type = ServiceMatchType::Regex;
    } else {
        return false;
    }
    return true;
}

} // namespace

ServiceProbeDatabase ServiceProbeDatabase::built_in()
{
    core::StatusCode status = core::StatusCode::Ok;
    return parse(kBuiltInDatabase, status);
}

ServiceProbeDatabase ServiceProbeDatabase::parse(std::string_view text, core::StatusCode &status)
{
    ServiceProbeDatabase database;
    status = core::StatusCode::Ok;
    if (text.size() > kMaximumDatabaseBytes) {
        status = core::StatusCode::ParseError;
        database.status_ = status;
        return database;
    }
    const auto fail = [&database, &status](core::StatusCode failure) {
        status = failure;
        database.status_ = status;
        database.probes_.clear();
        return database;
    };
    try {
        std::istringstream lines{std::string{text}};
        std::string line;
        ServiceProbeDefinition *current = nullptr;
        std::vector<std::string> tokens;
        while (std::getline(lines, line)) {
            if (line.size() > kMaximumLineBytes) {
                status = core::StatusCode::ParseError;
                return fail(status);
            }
            const std::string_view content = trim(without_comment(line));
            if (content.empty()) {
                continue;
            }
            if (!tokenize(content, tokens) || tokens.empty()) {
                status = core::StatusCode::ParseError;
                database.status_ = status;
                database.probes_.clear();
                return database;
            }
            if (tokens[0] == "Probe") {
                if (tokens.size() < 3U || (tokens[1] != "TCP" && tokens[1] != "UDP")) {
                    status = core::StatusCode::ParseError;
                    return fail(status);
                }
                if (database.probes_.size() >= kMaximumProbeCount) {
                    status = core::StatusCode::ParseError;
                    return fail(status);
                }
                ServiceProbeDefinition definition;
                definition.id = tokens[2];
                definition.name = tokens[2];
                definition.protocol = tokens[1] == "UDP" ? TransportProtocol::Udp : TransportProtocol::Tcp;
                for (std::size_t index = 3U; index < tokens.size(); ++index) {
                    std::string_view key;
                    std::string_view value;
                    if (!split_assignment(tokens[index], key, value)) {
                        status = core::StatusCode::ParseError;
                        return fail(status);
                    }
                    if (key == "rarity") {
                        if (!parse_unsigned(value, definition.rarity) || definition.rarity == 0U) {
                            status = core::StatusCode::ParseError;
                            database.status_ = status;
                            return database;
                        }
                    } else if (key == "ports") {
                        const portscan::PortSelection selection = definition.protocol == TransportProtocol::Udp
                                                                        ? portscan::parse_udp_ports(value)
                                                                        : portscan::parse_tcp_ports(value);
                        if (selection.status != core::StatusCode::Ok) {
                            status = core::StatusCode::ParseError;
                            database.status_ = status;
                            return database;
                        }
                        definition.port_hints = selection.ports;
                    } else if (key == "protocol") {
                        const bool protocol_matches =
                            (value == "tcp" && definition.protocol == TransportProtocol::Tcp) ||
                            (value == "udp" && definition.protocol == TransportProtocol::Udp);
                        if (!protocol_matches) {
                            status = core::StatusCode::ParseError;
                            return fail(status);
                        }
                    } else {
                        status = core::StatusCode::ParseError;
                        return fail(status);
                    }
                }
                database.probes_.push_back(std::move(definition));
                current = &database.probes_.back();
            } else if (tokens[0] == "send") {
                if (current == nullptr || tokens.size() != 2U) {
                    status = core::StatusCode::ParseError;
                    return fail(status);
                }
                current->payload = tokens[1];
            } else if (tokens[0] == "match") {
                if (current == nullptr) {
                    status = core::StatusCode::ParseError;
                    return fail(status);
                }
                ServiceMatchRule rule;
                bool has_pattern = false;
                bool has_service = false;
                bool has_confidence = false;
                for (std::size_t index = 1U; index < tokens.size(); ++index) {
                    std::string_view key;
                    std::string_view value;
                    if (!split_assignment(tokens[index], key, value)) {
                        status = core::StatusCode::ParseError;
                        return fail(status);
                    }
                    if (key == "type") {
                        if (!parse_match_type(value, rule.type)) {
                            status = core::StatusCode::ParseError;
                            database.status_ = status;
                            return database;
                        }
                    } else if (key == "pattern") {
                        if (value.size() > kMaximumPatternBytes) {
                            status = core::StatusCode::ParseError;
                            return fail(status);
                        }
                        rule.pattern = value;
                        has_pattern = true;
                    } else if (key == "service") {
                        rule.service = value;
                        has_service = true;
                    } else if (key == "product") {
                        rule.product = value;
                    } else if (key == "version") {
                        rule.version = value;
                    } else if (key == "extra") {
                        rule.extra = value;
                    } else if (key == "confidence") {
                        if (!parse_confidence(value, rule.confidence)) {
                            status = core::StatusCode::ParseError;
                            database.status_ = status;
                            return database;
                        }
                        has_confidence = true;
                    } else {
                        status = core::StatusCode::ParseError;
                        return fail(status);
                    }
                }
                if (!has_pattern || !has_service || !has_confidence ||
                    current->rules.size() >= kMaximumRulesPerProbe) {
                    status = core::StatusCode::ParseError;
                    return fail(status);
                }
                if (rule.type == ServiceMatchType::Regex) {
                    try {
                        rule.compiled_regex.emplace(rule.pattern, std::regex::ECMAScript);
                    } catch (const std::regex_error &) {
                        status = core::StatusCode::ParseError;
                        return fail(status);
                    }
                }
                const std::size_t base_specificity = rule.type == ServiceMatchType::Exact
                                                          ? 4000U
                                                          : rule.type == ServiceMatchType::Prefix
                                                                ? 3000U
                                                                : rule.type == ServiceMatchType::Substring ? 2000U : 1000U;
                rule.specificity = base_specificity + rule.pattern.size();
                current->rules.push_back(std::move(rule));
            } else {
                status = core::StatusCode::ParseError;
                return fail(status);
            }
        }
        if (database.probes_.empty()) {
            status = core::StatusCode::ParseError;
        }
    } catch (const std::bad_alloc &) {
        status = core::StatusCode::MemoryError;
    }
    database.status_ = status;
    if (status != core::StatusCode::Ok) {
        database.probes_.clear();
    }
    return database;
}

ServiceProbeDatabase ServiceProbeDatabase::load_file(const std::string &path, core::StatusCode &status)
{
    std::ifstream input(path);
    if (!input) {
        status = core::StatusCode::NotFound;
        ServiceProbeDatabase database;
        database.status_ = status;
        return database;
    }
    std::string contents;
    contents.reserve(kMaximumDatabaseBytes);
    std::array<char, 4096> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            const std::size_t bytes = static_cast<std::size_t>(count);
            if (bytes > kMaximumDatabaseBytes - contents.size()) {
                status = core::StatusCode::ParseError;
                return {};
            }
            contents.append(buffer.data(), bytes);
        }
    }
    if (input.bad()) {
        status = core::StatusCode::IoError;
        return {};
    }
    return parse(contents, status);
}

const std::vector<ServiceProbeDefinition> &ServiceProbeDatabase::probes() const noexcept
{
    return probes_;
}

core::StatusCode ServiceProbeDatabase::status() const noexcept
{
    return status_;
}

std::vector<std::size_t> ServiceProbeDatabase::ordered_probe_indices(
    const DetectionPort &port,
    std::size_t max_count) const
{
    std::vector<std::size_t> indices;
    if (max_count == 0U || status_ != core::StatusCode::Ok) {
        return indices;
    }
    for (std::size_t index = 0U; index < probes_.size(); ++index) {
        if (probes_[index].protocol == port.protocol) {
            indices.push_back(index);
        }
    }
    const auto has_hint = [this, &port](std::size_t index) {
        return std::any_of(
            probes_[index].port_hints.begin(),
            probes_[index].port_hints.end(),
            [&port](const DetectionPort &hint) { return hint.number == port.number; });
    };
    const bool any_matching_hint = std::any_of(indices.begin(), indices.end(), has_hint);
    std::stable_sort(indices.begin(), indices.end(), [this, &has_hint, any_matching_hint](std::size_t left, std::size_t right) {
        const bool left_hint = has_hint(left);
        const bool right_hint = has_hint(right);
        if (left_hint != right_hint) {
            return left_hint > right_hint;
        }
        if (!any_matching_hint) {
            const bool left_generic = probes_[left].port_hints.empty();
            const bool right_generic = probes_[right].port_hints.empty();
            if (left_generic != right_generic) {
                return left_generic > right_generic;
            }
        }
        if (probes_[left].rarity != probes_[right].rarity) {
            return probes_[left].rarity < probes_[right].rarity;
        }
        if (probes_[left].name != probes_[right].name) {
            return probes_[left].name < probes_[right].name;
        }
        return left < right;
    });
    if (indices.size() > max_count) {
        indices.resize(max_count);
    }
    return indices;
}

const char *service_match_type_name(ServiceMatchType type) noexcept
{
    switch (type) {
    case ServiceMatchType::Exact:
        return "exact";
    case ServiceMatchType::Prefix:
        return "prefix";
    case ServiceMatchType::Substring:
        return "substring";
    case ServiceMatchType::Regex:
        return "regex";
    default:
        return "unknown";
    }
}

} // namespace skan::detect
