#include <cassert>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "target/target_engine.hpp"

namespace {

skan::core::IpAddress ip_address(std::string_view text)
{
    const auto parsed = skan::target::parse_ip_address(text);
    assert(parsed.has_value());
    return *parsed;
}

skan::target::IPv4Address address(std::string_view text)
{
    const auto parsed = skan::target::parse_ipv4(text);
    assert(parsed.has_value());
    return *parsed;
}

} // namespace

int main()
{
    using namespace skan::target;

    const TargetParseResult parsed = TargetParser::parse("192.168.1.1, 192.168.1.0/30,192.168.1.10-192.168.1.12,example.com");
    assert(parsed.success());
    assert(parsed.specifications.size() == 4U);
    assert(parsed.specifications[0].kind == TargetKind::IPv4);
    assert(parsed.specifications[1].kind == TargetKind::IPv4Cidr);
    assert(parsed.specifications[1].prefix_length == 30U);
    assert(parsed.specifications[2].kind == TargetKind::IPv4Range);
    assert(parsed.specifications[2].first_address == address("192.168.1.10"));
    assert(parsed.specifications[2].last_address == address("192.168.1.12"));
    assert(parsed.specifications[3].kind == TargetKind::Hostname);
    assert(parsed.specifications[3].hostname == "example.com");

    const TargetParseResult ipv6_parsed = TargetParser::parse("::1,2001:db8::/64,2001:db8::1-2001:db8::3");
    assert(ipv6_parsed.success());
    assert(ipv6_parsed.specifications[0].kind == TargetKind::IPv6);
    assert(ipv6_parsed.specifications[0].first_ip == ip_address("::1"));
    assert(ipv6_parsed.specifications[1].kind == TargetKind::IPv6Cidr);
    assert(ipv6_parsed.specifications[1].prefix_length == 64U);
    assert(ipv6_parsed.specifications[2].kind == TargetKind::IPv6Range);

    const TargetResolutionResult cidr = TargetEngine::resolve("192.168.1.0/30");
    assert(cidr.success());
    assert(cidr.target_set.size() == 4U);
    assert(cidr.target_set.targets[0].address == address("192.168.1.0"));
    assert(cidr.target_set.targets[3].address == address("192.168.1.3"));

    const TargetResolutionResult cidr24 = TargetEngine::resolve("192.168.2.0/24");
    assert(cidr24.success());
    assert(cidr24.target_set.size() == 256U);

    const TargetResolutionResult cidr16 = TargetEngine::resolve("198.51.0.0/16", TargetLimits{65536U, 64U});
    assert(cidr16.success());
    assert(cidr16.target_set.size() == 65536U);

    const TargetResolutionResult host100k = TargetEngine::resolve(
        "10.0.0.1-10.1.134.160", TargetLimits{100000U, 64U});
    assert(host100k.success());
    assert(host100k.target_set.size() == 100000U);

    const TargetResolutionResult host32 = TargetEngine::resolve("192.168.1.7/32");
    assert(host32.success());
    assert(host32.target_set.size() == 1U);
    assert(host32.target_set.targets.front().address == address("192.168.1.7"));

    const TargetResolutionResult range = TargetEngine::resolve("192.168.1.10-192.168.1.12");
    assert(range.success());
    assert(range.target_set.size() == 3U);

    const TargetResolutionResult localhost = TargetEngine::resolve("localhost");
    assert(localhost.success());
    assert(!localhost.target_set.empty());

    const TargetResolutionResult ipv6_single = TargetEngine::resolve("2001:db8::1");
    assert(ipv6_single.success());
    assert(ipv6_single.target_set.size() == 1U);
    assert(ipv6_single.target_set.targets.front().ip_address == ip_address("2001:db8::1"));
    assert(ipv6_single.target_set.targets.front().ip_address.to_string() == "2001:db8::1");

    const TargetResolutionResult ipv6_127 = TargetEngine::resolve("2001:db8::/127");
    assert(ipv6_127.success());
    assert(ipv6_127.target_set.size() == 2U);
    assert(ipv6_127.target_set.targets[0].ip_address == ip_address("2001:db8::"));
    assert(ipv6_127.target_set.targets[1].ip_address == ip_address("2001:db8::1"));

    const TargetResolutionResult ipv6_range = TargetEngine::resolve("2001:db8::1-2001:db8::3");
    assert(ipv6_range.success());
    assert(ipv6_range.target_set.size() == 3U);

    const auto scoped = parse_ip_address("fe80::1%lo");
    assert(scoped.has_value());
    assert(scoped->is_ipv6());
    assert(scoped->has_scope());
    assert(scoped->scope == std::optional<std::string>{"lo"});
    assert(scoped->to_string() == "fe80::1%lo");
    const TargetResolutionResult scoped_target = TargetEngine::resolve("fe80::1%lo");
    assert(scoped_target.success());
    assert(scoped_target.target_set.targets.front().ip_address == *scoped);
    assert(TargetEngine::resolve("fe80::1%lo/128").success());
    const TargetParseResult mixed_scoped_range = TargetParser::parse("fe80::1%lo-fe80::2%eth0");
    assert(!mixed_scoped_range.success());
    assert(mixed_scoped_range.error.code == TargetErrorCode::InvalidRange);
    const std::vector<ResolvedTarget> scoped_duplicates = {
        ResolvedTarget{0U, std::nullopt, ip_address("fe80::1%lo")},
        ResolvedTarget{0U, std::nullopt, ip_address("fe80::1%eth0")},
        ResolvedTarget{0U, std::nullopt, ip_address("fe80::1%lo")}};
    assert(TargetDeduplicator::deduplicate(scoped_duplicates).size() == 2U);

    const TargetResolutionResult mixed = TargetEngine::resolve("::1,127.0.0.1");
    assert(mixed.success());
    assert(mixed.target_set.size() == 2U);
    assert(mixed.target_set.targets[0].ip_address.is_ipv4());
    assert(mixed.target_set.targets[1].ip_address.is_ipv6());

    const TargetResolutionResult ipv6_exhausted = TargetEngine::resolve("2001:db8::/64");
    assert(!ipv6_exhausted.success());
    assert(ipv6_exhausted.status == skan::core::StatusCode::ResourceExhausted);
    assert(ipv6_exhausted.error.code == TargetErrorCode::ResourceExhausted);

    const TargetResolutionResult ordered = TargetEngine::resolve("10.0.0.10,10.0.0.2,10.0.0.1,10.0.0.2");
    assert(ordered.success());
    assert(ordered.target_set.size() == 3U);
    assert(format_ipv4(ordered.target_set.targets[0].address) == "10.0.0.1");
    assert(format_ipv4(ordered.target_set.targets[1].address) == "10.0.0.2");
    assert(format_ipv4(ordered.target_set.targets[2].address) == "10.0.0.10");

    const HostnameResolver controlled_resolver = [](std::string_view hostname, std::size_t max_results) {
        assert(hostname == "lab.example");
        if (max_results < 2U) {
            return HostnameResolution{skan::core::StatusCode::ResourceExhausted, {}, "too many A/AAAA records", {}};
        }
        return HostnameResolution{skan::core::StatusCode::Ok, {address("10.0.0.10"), address("10.0.0.2")}, {}, {}};
    };
    const TargetResolutionResult hostname = TargetEngine::resolve("lab.example,10.0.0.1,10.0.0.10", {}, controlled_resolver);
    assert(hostname.success());
    assert(hostname.target_set.size() == 3U);
    assert(hostname.target_set.targets[0].source_hostname == std::nullopt);
    assert(hostname.target_set.targets[1].source_hostname == std::optional<std::string>{"lab.example"});
    assert(hostname.target_set.targets[2].source_hostname == std::optional<std::string>{"lab.example"});

    TargetLimits limited;
    limited.max_targets = 4U;
    const TargetResolutionResult exhausted = TargetEngine::resolve("0.0.0.0/0", limited);
    assert(!exhausted.success());
    assert(exhausted.status == skan::core::StatusCode::ResourceExhausted);
    assert(exhausted.error.code == TargetErrorCode::ResourceExhausted);

    const TargetResolutionResult hard_limit_exhausted = TargetEngine::resolve(
        "::1", TargetLimits{TargetLimits::kMaximumTargets + 1U, 64U});
    assert(!hard_limit_exhausted.success());
    assert(hard_limit_exhausted.status == skan::core::StatusCode::ResourceExhausted);
    assert(hard_limit_exhausted.error.code == TargetErrorCode::ResourceExhausted);
    const TargetResolutionResult hostname_hard_limit_exhausted = TargetEngine::resolve(
        "lab.example", TargetLimits{4096U, TargetLimits::kMaximumHostnameResults + 1U}, controlled_resolver);
    assert(!hostname_hard_limit_exhausted.success());
    assert(hostname_hard_limit_exhausted.status == skan::core::StatusCode::ResourceExhausted);
    assert(hostname_hard_limit_exhausted.error.code == TargetErrorCode::ResourceExhausted);

    const TargetResolutionResult hostname_exhausted = TargetEngine::resolve("lab.example", TargetLimits{4096U, 1U}, controlled_resolver);
    assert(!hostname_exhausted.success());
    assert(hostname_exhausted.status == skan::core::StatusCode::ResourceExhausted);
    assert(hostname_exhausted.error.code == TargetErrorCode::ResourceExhausted);

    const std::vector<std::pair<std::string_view, TargetErrorCode>> invalid = {
        {"", TargetErrorCode::EmptyTargetSet},
        {"999.999.999.999", TargetErrorCode::InvalidIPv4},
        {"192.168.1.0/33", TargetErrorCode::InvalidCIDR},
        {"192.168.1.20-192.168.1.10", TargetErrorCode::InvalidRange},
        {"-bad.example", TargetErrorCode::InvalidHostname},
        {"192.168.1.1,,192.168.1.2", TargetErrorCode::InvalidTarget},
        {"2001:db8:::1", TargetErrorCode::InvalidTarget},
        {"fe80::1%", TargetErrorCode::InvalidScope},
        {"fe80::1%lo%eth0", TargetErrorCode::InvalidScope},
        {"2001:db8::/129", TargetErrorCode::InvalidCIDR}};
    for (const auto &[input, expected] : invalid) {
        const TargetParseResult result = TargetParser::parse(input);
        assert(!result.success());
        assert(result.error.code == expected);
    }

    const TargetResolutionResult missing = TargetEngine::resolve(
        "missing.example",
        {},
        [](std::string_view, std::size_t) {
            return HostnameResolution{skan::core::StatusCode::NotFound, {}, "controlled DNS failure", {}};
        });
    assert(!missing.success());
    assert(missing.status == skan::core::StatusCode::NotFound);
    assert(missing.error.code == TargetErrorCode::ResolutionFailed);
    assert(std::string{target_error_name(TargetErrorCode::ResourceExhausted)} == "RESOURCE_EXHAUSTED");
    return 0;
}
