#include <cassert>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "target/target_engine.hpp"

namespace {

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

    const TargetResolutionResult ordered = TargetEngine::resolve("10.0.0.10,10.0.0.2,10.0.0.1,10.0.0.2");
    assert(ordered.success());
    assert(ordered.target_set.size() == 3U);
    assert(format_ipv4(ordered.target_set.targets[0].address) == "10.0.0.1");
    assert(format_ipv4(ordered.target_set.targets[1].address) == "10.0.0.2");
    assert(format_ipv4(ordered.target_set.targets[2].address) == "10.0.0.10");

    const HostnameResolver controlled_resolver = [](std::string_view hostname, std::size_t max_results) {
        assert(hostname == "lab.example");
        if (max_results < 2U) {
            return HostnameResolution{skan::core::StatusCode::ResourceExhausted, {}, "too many A records"};
        }
        return HostnameResolution{skan::core::StatusCode::Ok, {address("10.0.0.10"), address("10.0.0.2")}, {}};
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
        {"::1", TargetErrorCode::UnsupportedTarget}};
    for (const auto &[input, expected] : invalid) {
        const TargetParseResult result = TargetParser::parse(input);
        assert(!result.success());
        assert(result.error.code == expected);
    }

    const TargetResolutionResult missing = TargetEngine::resolve(
        "missing.example",
        {},
        [](std::string_view, std::size_t) {
            return HostnameResolution{skan::core::StatusCode::NotFound, {}, "controlled DNS failure"};
        });
    assert(!missing.success());
    assert(missing.status == skan::core::StatusCode::NotFound);
    assert(missing.error.code == TargetErrorCode::ResolutionFailed);
    assert(std::string{target_error_name(TargetErrorCode::ResourceExhausted)} == "RESOURCE_EXHAUSTED");
    return 0;
}
