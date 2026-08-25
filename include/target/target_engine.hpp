#ifndef SKAN_TARGET_TARGET_ENGINE_HPP
#define SKAN_TARGET_TARGET_ENGINE_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"

namespace skan::target {

using IPv4Address = std::uint32_t;

enum class TargetKind : std::uint8_t {
    IPv4 = 0,
    Hostname,
    IPv4Cidr,
    IPv4Range,
    IPv6,
    IPv6Cidr,
    IPv6Range
};

enum class TargetErrorCode : std::uint8_t {
    None = 0,
    InvalidTarget,
    InvalidIPv4,
    InvalidCIDR,
    InvalidRange,
    InvalidHostname,
    ResolutionFailed,
    ResourceExhausted,
    UnsupportedTarget,
    EmptyTargetSet
};

const char *target_kind_name(TargetKind kind) noexcept;
const char *target_error_name(TargetErrorCode code) noexcept;

struct TargetError final {
    TargetErrorCode code{TargetErrorCode::None};
    std::string message;

    bool ok() const noexcept { return code == TargetErrorCode::None; }
};

struct TargetSpec final {
    TargetKind kind{TargetKind::IPv4};
    std::string original;
    IPv4Address first_address{0U};
    IPv4Address last_address{0U};
    std::uint8_t prefix_length{32U};
    std::string hostname;
    core::IpAddress first_ip{};
    core::IpAddress last_ip{};
};

struct ResolvedTarget final {
    IPv4Address address{0U};
    std::optional<std::string> source_hostname;
    core::IpAddress ip_address{};
};

struct TargetSet final {
    std::vector<ResolvedTarget> targets;

    bool empty() const noexcept { return targets.empty(); }
    std::size_t size() const noexcept { return targets.size(); }
};

struct TargetLimits final {
    std::size_t max_targets{4096U};
    std::size_t max_hostname_results{64U};
};

struct TargetParseResult final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<TargetSpec> specifications;
    TargetError error;

    bool success() const noexcept
    {
        return status == core::StatusCode::Ok && error.ok() && !specifications.empty();
    }
};

struct HostnameResolution final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<IPv4Address> addresses;
    std::string message;
    std::vector<core::IpAddress> ip_addresses;
};

using HostnameResolver = std::function<HostnameResolution(std::string_view hostname, std::size_t max_results)>;

struct TargetExpansionResult final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<ResolvedTarget> targets;
    TargetError error;

    bool success() const noexcept
    {
        return status == core::StatusCode::Ok && error.ok();
    }
};

struct TargetResolutionResult final {
    core::StatusCode status{core::StatusCode::Ok};
    TargetSet target_set;
    TargetError error;

    bool success() const noexcept
    {
        return status == core::StatusCode::Ok && error.ok() && !target_set.empty();
    }
};

std::optional<IPv4Address> parse_ipv4(std::string_view text) noexcept;
std::optional<core::IpAddress> parse_ip_address(std::string_view text) noexcept;
std::string format_ipv4(IPv4Address address);
std::string format_ip_address(const core::IpAddress &address);

class TargetParser final {
public:
    static TargetParseResult parse(std::string_view input);
};

class TargetResolver final {
public:
    /**
     * Expand parsed specifications and resolve hostnames. The default resolver
     * calls getaddrinfo(AF_INET) synchronously; callers should invoke this
     * boundary before entering the scan IOEngine loop.
     */
    static TargetExpansionResult expand(
        const std::vector<TargetSpec> &specifications,
        TargetLimits limits = {},
        HostnameResolver resolver = {});
};

class TargetDeduplicator final {
public:
    static std::vector<ResolvedTarget> deduplicate(std::vector<ResolvedTarget> targets);
};

class TargetNormalizer final {
public:
    static void sort_numeric(std::vector<ResolvedTarget> &targets) noexcept;
};

class TargetEngine final {
public:
    static TargetParseResult parse(std::string_view input);

    static TargetResolutionResult resolve(
        std::string_view input,
        TargetLimits limits = {},
        HostnameResolver resolver = {});

    static TargetResolutionResult resolve(
        const std::vector<TargetSpec> &specifications,
        TargetLimits limits = {},
        HostnameResolver resolver = {});
};

} // namespace skan::target

#endif // SKAN_TARGET_TARGET_ENGINE_HPP
