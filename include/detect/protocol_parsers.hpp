#ifndef SKAN_DETECT_PROTOCOL_PARSERS_HPP
#define SKAN_DETECT_PROTOCOL_PARSERS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace skan::detect {

enum class HttpParseState { Incomplete, Malformed, Headers, Complete };

// Views refer to the input response. Only the bounded, dechunked body is owned.
struct HttpResponse final {
    HttpParseState state{HttpParseState::Incomplete};
    std::string_view protocol_version;
    std::uint16_t status_code{0U};
    std::string_view headers;
    std::string_view server;
    bool ambiguous_server{false};
    bool identity_encoding{true};
    bool json_content{false};
    std::string body;
};

HttpResponse parse_http_response(std::string_view response, bool terminal);

struct SearchIdentity final {
    std::string service;
    std::string product;
    std::string version;
};

// Complete JSON object only; duplicate decoded keys, invalid UTF-8/escapes,
// wrong types, nested collisions, and conflicting distribution markers fail.
std::optional<SearchIdentity> parse_search_identity(std::string_view body);

struct ProtocolIdentity final {
    std::string service;
    std::string product;
    std::string version;
    std::string extra;
    std::string validator;
    std::string version_source;
    std::string protocol_version;
    bool provisional{false};
};

bool has_api_validator(std::string_view family) noexcept;
std::optional<ProtocolIdentity> parse_api_identity(
    std::string_view family, std::string_view request, const HttpResponse &http);
std::optional<ProtocolIdentity> parse_nats_info(std::string_view response);
std::optional<ProtocolIdentity> parse_minecraft_status(std::string_view response);

struct ZooKeeperIdentity final {
    std::string version;
    std::string mode;
};

std::optional<ZooKeeperIdentity> parse_zookeeper_srvr(std::string_view response, bool terminal);

} // namespace skan::detect
#endif
