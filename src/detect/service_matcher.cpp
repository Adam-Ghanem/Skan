#include "detect/service_matcher.hpp"

#include <charconv>
#include <cstdint>
#include <regex>
#include <span>

namespace skan::detect {
namespace {

constexpr std::size_t kMaximumMatchResponseBytes = 8192U;

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
    // Anchored capture rules carry structured protocol/version evidence.
    return rule.pattern.find('(') != std::string::npos && !rule.pattern.empty() && rule.pattern.front() == '^'
               ? 4U
               : 1U;
}

bool rule_matches(
    const ServiceMatchRule &rule,
    std::string_view response,
    std::match_results<std::string::const_iterator> &matches,
    std::string &owned_response)
{
    switch (rule.type) {
    case ServiceMatchType::Exact:
        return response == rule.pattern;
    case ServiceMatchType::Prefix:
        return response.size() >= rule.pattern.size() && response.substr(0U, rule.pattern.size()) == rule.pattern;
    case ServiceMatchType::Suffix:
        return response.size() >= rule.pattern.size() &&
               response.substr(response.size() - rule.pattern.size()) == rule.pattern;
    case ServiceMatchType::Substring:
        return response.find(rule.pattern) != std::string_view::npos;
    case ServiceMatchType::Regex:
        owned_response.assign(response);
        if (!rule.compiled_regex.has_value()) {
            return false;
        }
        return std::regex_search(owned_response.cbegin(), owned_response.cend(), matches, *rule.compiled_regex);
    default:
        return false;
    }
}

} // namespace

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
        const bool better = !best.matched || candidate.strength > best.strength ||
                            (candidate.strength == best.strength && candidate.priority > best.priority) ||
                            (candidate.strength == best.strength && candidate.priority == best.priority &&
                             candidate.confidence > best.confidence) ||
                            (candidate.strength == best.strength && candidate.priority == best.priority &&
                             candidate.confidence == best.confidence &&
                             candidate.specificity > best.specificity) ||
                            (candidate.strength == best.strength && candidate.priority == best.priority &&
                             candidate.confidence == best.confidence &&
                             candidate.specificity == best.specificity && candidate.rule_index < best.rule_index);
        if (better) {
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
