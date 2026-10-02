#include "detect/service_matcher.hpp"

#include <charconv>
#include <cstdint>
#include <regex>
#include <span>

namespace skan::detect {
namespace {

constexpr std::size_t kMaximumMatchResponseBytes = 8192U;
constexpr double kMinimumPublishedSoftMatchConfidence = 0.60;

std::optional<MqttConnackEvidence> validate_mqtt_connack(
    const ServiceProbeDefinition &probe, std::string_view response) noexcept
{
    // Deliberately scoped to the installed, credential-free clean-session
    // CONNECT. A probe name, port hint, or unsolicited CONNACK is not evidence.
    static constexpr char request[] = "\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04skan";
    if (probe.protocol != TransportProtocol::Tcp ||
        probe.payload != std::string_view{request, sizeof(request) - 1U} ||
        response.size() < 4U) {
        return std::nullopt;
    }
    const auto byte = [&](std::size_t index) {
        return static_cast<unsigned char>(response[index]);
    };
    // OASIS MQTT 3.1.1 sections 3.2.1/3.2.2: exact fixed header and
    // remaining length; clean-session request requires Session Present = 0;
    // all other acknowledgement flag bits and return codes 6..255 are reserved.
    if (byte(0U) != 0x20U || byte(1U) != 0x02U || byte(2U) != 0U || byte(3U) > 5U) {
        return std::nullopt;
    }
    // Validate the first complete frame only. Coalesced later packets cannot
    // change its evidence; partial first frames never produce a match.
    return MqttConnackEvidence{static_cast<std::uint8_t>(byte(3U))};
}

std::string_view first_ssh_identification_line(std::string_view response) noexcept
{
    std::size_t line_start = 0U;
    while (line_start < response.size()) {
        const std::size_t newline = response.find('\n', line_start);
        std::size_t line_end = newline == std::string_view::npos ? response.size() : newline;
        if (line_end > line_start && response[line_end - 1U] == '\r') {
            --line_end;
        }
        const std::string_view line = response.substr(line_start, line_end - line_start);
        if (line.starts_with("SSH-")) {
            return line;
        }
        if (newline == std::string_view::npos) {
            break;
        }
        line_start = newline + 1U;
    }
    return {};
}

bool is_ssh_identification_rule(const ServiceMatchRule &rule) noexcept
{
    if (rule.service != "ssh") {
        return false;
    }
    if (rule.type == ServiceMatchType::Regex) {
        return rule.pattern.starts_with("^SSH-");
    }
    if (rule.type == ServiceMatchType::Prefix) {
        return rule.pattern.starts_with("SSH-");
    }
    return false;
}

std::string expand_template(
    std::string_view value,
    const std::match_results<std::string::const_iterator> *matches)
{
    if (matches == nullptr || value.empty()) {
        return std::string{value};
    }
    std::string output;
    for (std::size_t index = 0U; index < value.size();) {
        if (value[index] != '$' || index + 1U >= value.size() ||
            value[index + 1U] < '0' || value[index + 1U] > '9') {
            output.push_back(value[index++]);
            continue;
        }
        std::size_t end = index + 1U;
        while (end < value.size() && value[end] >= '0' && value[end] <= '9') {
            ++end;
        }
        unsigned int group = 0U;
        const auto parsed = std::from_chars(value.data() + index + 1U, value.data() + end, group, 10);
        if (parsed.ec == std::errc{} && group < matches->size() && (*matches)[group].matched) {
            output += (*matches)[group].str();
        } else {
            output.append(value, index, end - index);
        }
        index = end;
    }
    return output;
}

std::size_t rule_priority(const ServiceMatchRule &rule) noexcept
{
    if (rule.type == ServiceMatchType::Exact) {
        return 4U;
    }
    if (rule.type == ServiceMatchType::Prefix) {
        return 3U;
    }
    if (rule.type == ServiceMatchType::Suffix) {
        return 3U;
    }
    if (rule.type == ServiceMatchType::Substring) {
        return 2U;
    }
    // An anchored regex constrains the beginning of the protocol response and is
    // structured evidence even when it does not need a capture group. This keeps
    // product-specific rules such as a fixed MQTT CONNACK above generic prefixes.
    return !rule.pattern.empty() && rule.pattern.front() == '^' ? 4U : 1U;
}

bool rule_matches(
    const ServiceMatchRule &rule,
    std::string_view response,
    std::match_results<std::string::const_iterator> &matches,
    std::string &owned_response)
{
    std::string_view match_response = response;
    if (is_ssh_identification_rule(rule)) {
        match_response = first_ssh_identification_line(response);
        if (match_response.empty()) {
            return false;
        }
    }

    switch (rule.type) {
    case ServiceMatchType::Exact:
        return match_response == rule.pattern;
    case ServiceMatchType::Prefix:
        return match_response.size() >= rule.pattern.size() &&
               match_response.substr(0U, rule.pattern.size()) == rule.pattern;
    case ServiceMatchType::Suffix:
        return match_response.size() >= rule.pattern.size() &&
               match_response.substr(match_response.size() - rule.pattern.size()) == rule.pattern;
    case ServiceMatchType::Substring:
        return match_response.find(rule.pattern) != std::string_view::npos;
    case ServiceMatchType::Regex:
        owned_response.assign(match_response);
        if (!rule.compiled_regex.has_value()) {
            return false;
        }
        return std::regex_search(owned_response.cbegin(), owned_response.cend(), matches, *rule.compiled_regex);
    default:
        return false;
    }
}

} // namespace

bool service_match_is_publishable(const ServiceMatchResult &match) noexcept
{
    return match.matched &&
           (match.strength == ServiceMatchStrength::Hard ||
            match.confidence >= kMinimumPublishedSoftMatchConfidence);
}

bool service_match_is_better(
    const ServiceMatchResult &candidate,
    const ServiceMatchResult &incumbent) noexcept
{
    if (!candidate.matched) {
        return false;
    }
    if (!incumbent.matched) {
        return true;
    }
    if (candidate.strength != incumbent.strength) {
        return candidate.strength > incumbent.strength;
    }
    const bool candidate_publishable = service_match_is_publishable(candidate);
    const bool incumbent_publishable = service_match_is_publishable(incumbent);
    if (candidate_publishable != incumbent_publishable) {
        return candidate_publishable;
    }
    if (candidate.priority != incumbent.priority) {
        return candidate.priority > incumbent.priority;
    }
    if (candidate.confidence != incumbent.confidence) {
        return candidate.confidence > incumbent.confidence;
    }
    if (candidate.specificity != incumbent.specificity) {
        return candidate.specificity > incumbent.specificity;
    }
    return false;
}

ServiceMatcher::ServiceMatcher(const ServiceProbeDatabase &database) noexcept : database_(database)
{
}

ServiceMatchResult ServiceMatcher::match(
    const ServiceProbeDefinition &probe,
    std::string_view response) const
{
    ServiceMatchResult best;
    if (database_.status() != core::StatusCode::Ok || response.empty() ||
        response.size() > kMaximumMatchResponseBytes) {
        return best;
    }
    std::string owned_response;
    for (std::size_t index = 0U; index < probe.rules.size(); ++index) {
        const ServiceMatchRule &rule = probe.rules[index];
        std::match_results<std::string::const_iterator> matches;
        if (!rule_matches(rule, response, matches, owned_response)) {
            continue;
        }
        ServiceMatchResult candidate;
        candidate.matched = true;
        candidate.service = expand_template(rule.service, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.product = expand_template(rule.product, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.version = expand_template(rule.version, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.extra = expand_template(rule.extra, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.hostname = expand_template(rule.hostname, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.tunnel = expand_template(rule.tunnel, rule.type == ServiceMatchType::Regex ? &matches : nullptr);
        candidate.strength = rule.strength;
        candidate.confidence = rule.confidence;
        candidate.priority = rule_priority(rule);
        candidate.specificity = rule.specificity;
        candidate.rule_index = index;
        if (candidate.service == "mqtt") {
            candidate.mqtt = validate_mqtt_connack(probe, response);
            if (!candidate.mqtt.has_value()) {
                continue;
            }
            // CONNACK identifies a protocol, not a broker implementation or
            // product release. Keep requested/accepted protocol in evidence.
            candidate.product.clear();
            candidate.version.clear();
        }
        if (service_match_is_better(candidate, best)) {
            if (candidate.tunnel == "tls" || candidate.service == "tls" || candidate.service == "https") {
                const auto *data = reinterpret_cast<const std::uint8_t *>(response.data());
                candidate.tls = parse_tls_metadata(std::span<const std::uint8_t>{data, response.size()});
            }
            best = std::move(candidate);
        }
    }
    return best;
}

} // namespace skan::detect
