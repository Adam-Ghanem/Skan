#include "target/target_engine.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <limits>
#include <memory>
#include <netdb.h>
#include <new>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <unordered_set>
#include <utility>

namespace skan::target {
namespace {

std::string_view trim(std::string_view value) noexcept
{
    std::size_t first = 0U;
    while (first < value.size() && (value[first] == ' ' || value[first] == '\t' || value[first] == '\r' || value[first] == '\n')) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && (value[last - 1U] == ' ' || value[last - 1U] == '\t' || value[last - 1U] == '\r' || value[last - 1U] == '\n')) {
        --last;
    }
    return value.substr(first, last - first);
}

std::optional<core::IpAddress> parse_ipv6_text(std::string_view text) noexcept
{
    if (text.empty() || text.find('%') != std::string_view::npos) {
        return std::nullopt;
    }
    in6_addr address{};
    const std::string value(text);
    if (::inet_pton(AF_INET6, value.c_str(), &address) != 1) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 16U> bytes{};
    std::copy(std::begin(address.s6_addr), std::end(address.s6_addr), bytes.begin());
    return core::IpAddress::from_ipv6(bytes);
}

std::optional<core::IpAddress> parse_any_ip(std::string_view text) noexcept
{
    if (const auto ipv4 = parse_ipv4(text); ipv4.has_value()) {
        return core::IpAddress::from_ipv4(*ipv4);
    }
    return parse_ipv6_text(text);
}

core::IpAddress mask_ipv6(core::IpAddress address, std::uint8_t prefix) noexcept
{
    const std::size_t full_bytes = static_cast<std::size_t>(prefix / 8U);
    const std::uint8_t remainder = static_cast<std::uint8_t>(prefix % 8U);
    for (std::size_t index = full_bytes + (remainder == 0U ? 0U : 1U); index < 16U; ++index) {
        address.bytes[index] = 0U;
    }
    if (remainder != 0U && full_bytes < 16U) {
        const std::uint8_t mask = static_cast<std::uint8_t>(0xFFU << (8U - remainder));
        address.bytes[full_bytes] = static_cast<std::uint8_t>(address.bytes[full_bytes] & mask);
    }
    return address;
}

core::IpAddress add_ipv6_offset(core::IpAddress address, std::uint64_t offset) noexcept
{
    for (std::size_t index = 16U; index-- > 8U;) {
        const std::uint16_t sum = static_cast<std::uint16_t>(address.bytes[index]) +
                                  static_cast<std::uint16_t>(offset & 0xFFU);
        address.bytes[index] = static_cast<std::uint8_t>(sum & 0xFFU);
        offset = (offset >> 8U) + static_cast<std::uint64_t>(sum >> 8U);
    }
    return address;
}

std::optional<std::uint64_t> ipv6_range_count(const core::IpAddress &first, const core::IpAddress &last) noexcept
{
    if (!first.is_ipv6() || !last.is_ipv6() ||
        !std::equal(first.bytes.begin(), first.bytes.begin() + 8, last.bytes.begin())) {
        return std::nullopt;
    }
    std::uint64_t first_low = 0U;
    std::uint64_t last_low = 0U;
    for (std::size_t index = 8U; index < 16U; ++index) {
        first_low = (first_low << 8U) | static_cast<std::uint64_t>(first.bytes[index]);
        last_low = (last_low << 8U) | static_cast<std::uint64_t>(last.bytes[index]);
    }
    const std::uint64_t difference = last_low - first_low;
    if (difference == std::numeric_limits<std::uint64_t>::max()) {
        return std::nullopt;
    }
    return difference + 1U;
}

bool looks_like_ipv4(std::string_view value) noexcept
{
    bool has_dot = false;
    bool has_digit = false;
    for (const char character : value) {
        if (character == '.') {
            has_dot = true;
        } else if (character >= '0' && character <= '9') {
            has_digit = true;
        } else {
            return false;
        }
    }
    return has_dot && has_digit;
}

bool valid_hostname(std::string_view hostname) noexcept
{
    if (hostname.empty() || hostname.size() > 253U || hostname.front() == '.' || hostname.back() == '.') {
        return false;
    }
    std::size_t label_start = 0U;
    while (label_start < hostname.size()) {
        const std::size_t separator = hostname.find('.', label_start);
        const std::size_t label_end = separator == std::string_view::npos ? hostname.size() : separator;
        const std::size_t label_size = label_end - label_start;
        if (label_size == 0U || label_size > 63U || hostname[label_start] == '-' || hostname[label_end - 1U] == '-') {
            return false;
        }
        for (std::size_t index = label_start; index < label_end; ++index) {
            const char character = hostname[index];
            const bool alpha = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
            const bool digit = character >= '0' && character <= '9';
            if (!alpha && !digit && character != '-') {
                return false;
            }
        }
        if (separator == std::string_view::npos) {
            break;
        }
        label_start = separator + 1U;
    }
    return true;
}

TargetError make_error(TargetErrorCode code, std::string message)
{
    return TargetError{code, std::move(message)};
}

TargetParseResult parse_one(std::string_view token)
{
    token = trim(token);
    if (token.empty()) {
        return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidTarget, "empty target specification")};
    }

    const std::size_t slash = token.find('/');
    if (slash != std::string_view::npos) {
        if (token.find('/', slash + 1U) != std::string_view::npos) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidCIDR, "CIDR contains more than one prefix separator: " + std::string(token))};
        }
        const std::string_view address_text = token.substr(0U, slash);
        const std::string_view prefix_text = token.substr(slash + 1U);
        unsigned int prefix = 0U;
        const char *first = prefix_text.data();
        const char *last = prefix_text.data() + static_cast<std::ptrdiff_t>(prefix_text.size());
        const auto parsed_prefix = std::from_chars(first, last, prefix, 10);
        const auto address = parse_any_ip(address_text);
        if (prefix_text.empty() || parsed_prefix.ec != std::errc{} || parsed_prefix.ptr != last || !address.has_value()) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidCIDR, "invalid IP CIDR: " + std::string(token))};
        }
        if (address->is_ipv4() && prefix <= 32U) {
            const auto ipv4 = parse_ipv4(address_text);
            if (!ipv4.has_value()) {
                return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidCIDR, "invalid IPv4 CIDR: " + std::string(token))};
            }
            return {core::StatusCode::Ok,
                    {TargetSpec{TargetKind::IPv4Cidr, std::string(token), *ipv4, *ipv4, static_cast<std::uint8_t>(prefix), {}, *address, *address}},
                    {}};
        }
        if (address->is_ipv6() && prefix <= 128U) {
            return {core::StatusCode::Ok,
                    {TargetSpec{TargetKind::IPv6Cidr, std::string(token), 0U, 0U, static_cast<std::uint8_t>(prefix), {}, *address, *address}},
                    {}};
        }
        return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidCIDR, "invalid IP CIDR: " + std::string(token))};
    }

    const std::size_t dash = token.find('-');
    if (dash != std::string_view::npos) {
        if (token.find('-', dash + 1U) != std::string_view::npos) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidRange, "range contains more than one separator: " + std::string(token))};
        }
        const std::string_view left_text = trim(token.substr(0U, dash));
        const std::string_view right_text = trim(token.substr(dash + 1U));
        const auto first_ip = parse_any_ip(left_text);
        const auto last_ip = parse_any_ip(right_text);
        const bool range_candidate = first_ip.has_value() || last_ip.has_value() ||
                                     looks_like_ipv4(left_text) || looks_like_ipv4(right_text) ||
                                     left_text.find(':') != std::string_view::npos || right_text.find(':') != std::string_view::npos;
        if (range_candidate) {
            if (!first_ip.has_value() || !last_ip.has_value() || first_ip->family != last_ip->family) {
                return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidRange, "invalid or mixed-family IP range: " + std::string(token))};
            }
            if (*last_ip < *first_ip) {
                return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidRange, "reversed IP range: " + std::string(token))};
            }
            if (first_ip->is_ipv4()) {
                const IPv4Address first_address = (static_cast<IPv4Address>(first_ip->bytes[0]) << 24U) |
                                                   (static_cast<IPv4Address>(first_ip->bytes[1]) << 16U) |
                                                   (static_cast<IPv4Address>(first_ip->bytes[2]) << 8U) |
                                                   static_cast<IPv4Address>(first_ip->bytes[3]);
                const IPv4Address last_address = (static_cast<IPv4Address>(last_ip->bytes[0]) << 24U) |
                                                  (static_cast<IPv4Address>(last_ip->bytes[1]) << 16U) |
                                                  (static_cast<IPv4Address>(last_ip->bytes[2]) << 8U) |
                                                  static_cast<IPv4Address>(last_ip->bytes[3]);
                return {core::StatusCode::Ok,
                        {TargetSpec{TargetKind::IPv4Range, std::string(token), first_address, last_address, 32U, {}, *first_ip, *last_ip}},
                        {}};
            }
            return {core::StatusCode::Ok,
                    {TargetSpec{TargetKind::IPv6Range, std::string(token), 0U, 0U, 128U, {}, *first_ip, *last_ip}},
                    {}};
        }
    }

    if (const auto address = parse_ipv4(token); address.has_value()) {
        return {core::StatusCode::Ok,
                {TargetSpec{TargetKind::IPv4, std::string(token), *address, *address, 32U, {}, core::IpAddress::from_ipv4(*address), core::IpAddress::from_ipv4(*address)}},
                {}};
    }
    if (looks_like_ipv4(token)) {
        return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidIPv4, "invalid IPv4 address: " + std::string(token))};
    }
    if (const auto address = parse_ipv6_text(token); address.has_value()) {
        return {core::StatusCode::Ok,
                {TargetSpec{TargetKind::IPv6, std::string(token), 0U, 0U, 128U, {}, *address, *address}},
                {}};
    }
    if (token.find(':') != std::string_view::npos) {
        return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidTarget, "invalid IPv6 address: " + std::string(token))};
    }
    if (!valid_hostname(token)) {
        return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidHostname, "invalid hostname: " + std::string(token))};
    }
    return {core::StatusCode::Ok,
            {TargetSpec{TargetKind::Hostname, std::string(token), 0U, 0U, 0U, std::string(token), {}, {}}},
            {}};
}

HostnameResolution resolve_hostname(std::string_view hostname, std::size_t max_results)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *addresses = nullptr;
    const std::string name(hostname);
    const int result = ::getaddrinfo(name.c_str(), nullptr, &hints, &addresses);
    if (result != 0) {
        return {core::StatusCode::NotFound, {}, std::string("hostname resolution failed for ") + name + ": " + ::gai_strerror(result), {}};
    }
    const std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addresses_guard(addresses, &::freeaddrinfo);

    HostnameResolution resolved;
    std::unordered_set<core::IpAddress, core::IpAddressHash> seen;
    try {
        seen.reserve(max_results);
    } catch (const std::bad_alloc &) {
        return {core::StatusCode::ResourceExhausted, {}, "unable to allocate hostname result set", {}};
    }
    for (const addrinfo *entry = addresses; entry != nullptr; entry = entry->ai_next) {
        if (entry->ai_addr == nullptr) {
            continue;
        }
        core::IpAddress address;
        if (entry->ai_family == AF_INET && entry->ai_addrlen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
            const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(entry->ai_addr);
            address = core::IpAddress::from_ipv4(ntohl(ipv4->sin_addr.s_addr));
        } else if (entry->ai_family == AF_INET6 && entry->ai_addrlen >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
            const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(entry->ai_addr);
            std::array<std::uint8_t, 16U> bytes{};
            std::copy(std::begin(ipv6->sin6_addr.s6_addr), std::end(ipv6->sin6_addr.s6_addr), bytes.begin());
            address = core::IpAddress::from_ipv6(bytes);
        } else {
            continue;
        }
        if (seen.insert(address).second) {
            if (seen.size() > max_results) {
                return {core::StatusCode::ResourceExhausted, {}, "hostname resolution exceeded --max-hostname-results", {}};
            }
            resolved.ip_addresses.push_back(address);
            if (address.is_ipv4()) {
                const IPv4Address value = (static_cast<IPv4Address>(address.bytes[0]) << 24U) |
                                           (static_cast<IPv4Address>(address.bytes[1]) << 16U) |
                                           (static_cast<IPv4Address>(address.bytes[2]) << 8U) |
                                           static_cast<IPv4Address>(address.bytes[3]);
                resolved.addresses.push_back(value);
            }
        }
    }
    if (resolved.ip_addresses.empty()) {
        return {core::StatusCode::NotFound, {}, std::string("hostname has no IPv4/IPv6 address records: ") + name, {}};
    }
    return resolved;
}

TargetResolutionResult failure(core::StatusCode status, TargetError target_error)
{
    return TargetResolutionResult{status, {}, std::move(target_error)};
}

} // namespace

const char *target_kind_name(TargetKind kind) noexcept
{
    switch (kind) {
    case TargetKind::IPv4:
        return "ipv4";
    case TargetKind::Hostname:
        return "hostname";
    case TargetKind::IPv4Cidr:
        return "ipv4-cidr";
    case TargetKind::IPv4Range:
        return "ipv4-range";
    case TargetKind::IPv6:
        return "ipv6";
    case TargetKind::IPv6Cidr:
        return "ipv6-cidr";
    case TargetKind::IPv6Range:
        return "ipv6-range";
    }
    return "unknown";
}

const char *target_error_name(TargetErrorCode code) noexcept
{
    switch (code) {
    case TargetErrorCode::None:
        return "OK";
    case TargetErrorCode::InvalidTarget:
        return "INVALID_TARGET";
    case TargetErrorCode::InvalidIPv4:
        return "INVALID_IPV4";
    case TargetErrorCode::InvalidCIDR:
        return "INVALID_CIDR";
    case TargetErrorCode::InvalidRange:
        return "INVALID_RANGE";
    case TargetErrorCode::InvalidHostname:
        return "INVALID_HOSTNAME";
    case TargetErrorCode::ResolutionFailed:
        return "RESOLUTION_FAILED";
    case TargetErrorCode::ResourceExhausted:
        return "RESOURCE_EXHAUSTED";
    case TargetErrorCode::UnsupportedTarget:
        return "UNSUPPORTED_TARGET";
    case TargetErrorCode::EmptyTargetSet:
        return "EMPTY_TARGET_SET";
    }
    return "UNKNOWN";
}

std::optional<IPv4Address> parse_ipv4(std::string_view text) noexcept
{
    if (text.empty()) {
        return std::nullopt;
    }
    IPv4Address result = 0U;
    std::size_t start = 0U;
    for (std::size_t component = 0U; component < 4U; ++component) {
        const std::size_t end = text.find('.', start);
        if ((component < 3U && end == std::string_view::npos) || (component == 3U && end != std::string_view::npos)) {
            return std::nullopt;
        }
        const std::size_t component_end = end == std::string_view::npos ? text.size() : end;
        if (component_end == start || component_end - start > 3U) {
            return std::nullopt;
        }
        unsigned int value = 0U;
        const char *first = text.data() + static_cast<std::ptrdiff_t>(start);
        const char *last = text.data() + static_cast<std::ptrdiff_t>(component_end);
        const auto parsed = std::from_chars(first, last, value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != last || value > 255U) {
            return std::nullopt;
        }
        result = (result << 8U) | static_cast<IPv4Address>(value);
        start = component_end + 1U;
    }
    return result;
}

std::optional<core::IpAddress> parse_ip_address(std::string_view text) noexcept
{
    return parse_any_ip(trim(text));
}

std::string format_ipv4(IPv4Address address)
{
    return std::to_string((address >> 24U) & 0xFFU) + "." + std::to_string((address >> 16U) & 0xFFU) + "." +
           std::to_string((address >> 8U) & 0xFFU) + "." + std::to_string(address & 0xFFU);
}

std::string format_ip_address(const core::IpAddress &address)
{
    return address.to_string();
}

TargetParseResult TargetParser::parse(std::string_view input)
{
    try {
        input = trim(input);
        if (input.empty()) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::EmptyTargetSet, "target input is empty")};
        }
        std::vector<TargetSpec> specifications;
        std::size_t start = 0U;
        while (start <= input.size()) {
            const std::size_t separator = input.find(',', start);
            const std::string_view token = input.substr(start, separator == std::string_view::npos ? input.size() - start : separator - start);
            const TargetParseResult parsed = parse_one(token);
            if (!parsed.success()) {
                return parsed;
            }
            specifications.push_back(parsed.specifications.front());
            if (separator == std::string_view::npos) {
                break;
            }
            start = separator + 1U;
        }
        return {core::StatusCode::Ok, std::move(specifications), {}};
    } catch (const std::bad_alloc &) {
        return {core::StatusCode::MemoryError, {}, make_error(TargetErrorCode::ResourceExhausted, "unable to allocate target specifications")};
    }
}

TargetExpansionResult TargetResolver::expand(
    const std::vector<TargetSpec> &specifications,
    TargetLimits limits,
    HostnameResolver resolver)
{
    try {
        if (specifications.empty()) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::EmptyTargetSet, "target specification set is empty")};
        }
        if (limits.max_targets == 0U || limits.max_hostname_results == 0U) {
            return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidTarget, "target limits must be positive")};
        }
        if (!resolver) {
            resolver = resolve_hostname;
        }

        std::vector<ResolvedTarget> expanded;
        expanded.reserve(std::min<std::size_t>(limits.max_targets, 1024U));
        std::unordered_set<core::IpAddress, core::IpAddressHash> seen;
        seen.reserve(std::min<std::size_t>(limits.max_targets, 1024U));
        const auto append = [&expanded, &seen, &limits](const core::IpAddress &address, const std::optional<std::string> &hostname) -> std::optional<TargetError> {
            if (!address.valid() || !seen.insert(address).second) {
                return std::nullopt;
            }
            if (seen.size() > limits.max_targets) {
                std::ostringstream message;
                message << "target expansion exceeded --max-targets=" << limits.max_targets;
                return make_error(TargetErrorCode::ResourceExhausted, message.str());
            }
            IPv4Address legacy_address = 0U;
            if (address.is_ipv4()) {
                legacy_address = (static_cast<IPv4Address>(address.bytes[0]) << 24U) |
                                 (static_cast<IPv4Address>(address.bytes[1]) << 16U) |
                                 (static_cast<IPv4Address>(address.bytes[2]) << 8U) |
                                 static_cast<IPv4Address>(address.bytes[3]);
            }
            expanded.push_back(ResolvedTarget{legacy_address, hostname, address});
            return std::nullopt;
        };

        for (const TargetSpec &specification : specifications) {
            if (specification.kind == TargetKind::Hostname) {
                HostnameResolution resolved;
                try {
                    resolved = resolver(specification.hostname, limits.max_hostname_results);
                } catch (const std::bad_alloc &) {
                    return {core::StatusCode::MemoryError, {}, make_error(TargetErrorCode::ResourceExhausted, "hostname resolution allocation failed")};
                } catch (const std::exception &exception) {
                    return {core::StatusCode::InternalError, {}, make_error(TargetErrorCode::ResolutionFailed, std::string("hostname resolver failed: ") + exception.what())};
                }
                if (resolved.status != core::StatusCode::Ok || (resolved.ip_addresses.empty() && resolved.addresses.empty())) {
                    const TargetErrorCode code = resolved.status == core::StatusCode::ResourceExhausted
                                                     ? TargetErrorCode::ResourceExhausted
                                                     : TargetErrorCode::ResolutionFailed;
                    const core::StatusCode status = resolved.status == core::StatusCode::Ok ? core::StatusCode::NotFound : resolved.status;
                    return {status, {}, make_error(code, resolved.message.empty() ? "hostname resolution failed: " + specification.hostname : resolved.message)};
                }
                if (resolved.ip_addresses.size() > limits.max_hostname_results) {
                    return {core::StatusCode::ResourceExhausted, {}, make_error(TargetErrorCode::ResourceExhausted, "hostname resolution exceeded --max-hostname-results")};
                }
                if (!resolved.ip_addresses.empty()) {
                    for (const core::IpAddress &address : resolved.ip_addresses) {
                        const auto append_error = append(address, specification.hostname);
                        if (append_error.has_value()) {
                            return {core::StatusCode::ResourceExhausted, {}, *append_error};
                        }
                    }
                } else {
                    for (const IPv4Address address : resolved.addresses) {
                        const auto append_error = append(core::IpAddress::from_ipv4(address), specification.hostname);
                        if (append_error.has_value()) {
                            return {core::StatusCode::ResourceExhausted, {}, *append_error};
                        }
                    }
                }
                continue;
            }

            std::uint64_t count = 1U;
            core::IpAddress first_ip = specification.first_ip;
            if (specification.kind == TargetKind::IPv4 || specification.kind == TargetKind::IPv4Cidr ||
                specification.kind == TargetKind::IPv4Range) {
                IPv4Address first_address = specification.first_address;
                if (specification.kind == TargetKind::IPv4Cidr) {
                    const std::uint32_t host_bits = 32U - specification.prefix_length;
                    count = std::uint64_t{1U} << host_bits;
                    const IPv4Address mask = specification.prefix_length == 0U
                                                 ? 0U
                                                 : static_cast<IPv4Address>(std::numeric_limits<std::uint32_t>::max() << host_bits);
                    first_address &= mask;
                } else if (specification.kind == TargetKind::IPv4Range) {
                    count = static_cast<std::uint64_t>(specification.last_address) - specification.first_address + 1U;
                }
                first_ip = core::IpAddress::from_ipv4(first_address);
                if (count > static_cast<std::uint64_t>(limits.max_targets)) {
                    std::ostringstream message;
                    message << "target expansion exceeded --max-targets=" << limits.max_targets << " for " << specification.original;
                    return {core::StatusCode::ResourceExhausted, {}, make_error(TargetErrorCode::ResourceExhausted, message.str())};
                }
                for (std::uint64_t offset = 0U; offset < count; ++offset) {
                    const auto append_error = append(core::IpAddress::from_ipv4(first_address + static_cast<IPv4Address>(offset)), std::nullopt);
                    if (append_error.has_value()) {
                        return {core::StatusCode::ResourceExhausted, {}, *append_error};
                    }
                }
                continue;
            }

            if (!first_ip.is_ipv6()) {
                return {core::StatusCode::InvalidArgument, {}, make_error(TargetErrorCode::InvalidTarget, "target has no typed IP address")};
            }
            if (specification.kind == TargetKind::IPv6Cidr) {
                first_ip = mask_ipv6(first_ip, specification.prefix_length);
                const std::uint32_t host_bits = 128U - specification.prefix_length;
                if (host_bits >= 64U) {
                    return {core::StatusCode::ResourceExhausted, {}, make_error(TargetErrorCode::ResourceExhausted, "IPv6 CIDR expansion exceeds --max-targets: " + specification.original)};
                }
                count = std::uint64_t{1U} << host_bits;
            } else if (specification.kind == TargetKind::IPv6Range) {
                const auto range_count = ipv6_range_count(specification.first_ip, specification.last_ip);
                if (!range_count.has_value()) {
                    return {core::StatusCode::ResourceExhausted, {}, make_error(TargetErrorCode::ResourceExhausted, "IPv6 range is too large to expand safely: " + specification.original)};
                }
                count = *range_count;
            }
            if (count > static_cast<std::uint64_t>(limits.max_targets)) {
                std::ostringstream message;
                message << "target expansion exceeded --max-targets=" << limits.max_targets << " for " << specification.original;
                return {core::StatusCode::ResourceExhausted, {}, make_error(TargetErrorCode::ResourceExhausted, message.str())};
            }
            for (std::uint64_t offset = 0U; offset < count; ++offset) {
                const auto append_error = append(add_ipv6_offset(first_ip, offset), std::nullopt);
                if (append_error.has_value()) {
                    return {core::StatusCode::ResourceExhausted, {}, *append_error};
                }
            }
        }
        return {core::StatusCode::Ok, std::move(expanded), {}};
    } catch (const std::bad_alloc &) {
        return {core::StatusCode::MemoryError, {}, make_error(TargetErrorCode::ResourceExhausted, "target expansion allocation failed")};
    }
}

std::vector<ResolvedTarget> TargetDeduplicator::deduplicate(std::vector<ResolvedTarget> targets)
{
    std::unordered_set<core::IpAddress, core::IpAddressHash> seen;
    std::vector<ResolvedTarget> unique;
    seen.reserve(targets.size());
    unique.reserve(targets.size());
    for (ResolvedTarget &target : targets) {
        if (!target.ip_address.valid()) {
            target.ip_address = core::IpAddress::from_ipv4(target.address);
        }
        if (seen.insert(target.ip_address).second) {
            unique.push_back(std::move(target));
        }
    }
    return unique;
}

void TargetNormalizer::sort_numeric(std::vector<ResolvedTarget> &targets) noexcept
{
    std::sort(targets.begin(), targets.end(), [](const ResolvedTarget &left, const ResolvedTarget &right) {
        const core::IpAddress left_address = left.ip_address.valid() ? left.ip_address : core::IpAddress::from_ipv4(left.address);
        const core::IpAddress right_address = right.ip_address.valid() ? right.ip_address : core::IpAddress::from_ipv4(right.address);
        return left_address < right_address;
    });
}

TargetParseResult TargetEngine::parse(std::string_view input)
{
    return TargetParser::parse(input);
}

TargetResolutionResult TargetEngine::resolve(std::string_view input, TargetLimits limits, HostnameResolver resolver)
{
    const TargetParseResult parsed = TargetParser::parse(input);
    if (!parsed.success()) {
        return failure(parsed.status, parsed.error);
    }
    return resolve(parsed.specifications, limits, std::move(resolver));
}

TargetResolutionResult TargetEngine::resolve(
    const std::vector<TargetSpec> &specifications,
    TargetLimits limits,
    HostnameResolver resolver)
{
    try {
        const TargetExpansionResult expanded = TargetResolver::expand(specifications, limits, std::move(resolver));
        if (!expanded.success()) {
            return failure(expanded.status, expanded.error);
        }
        TargetSet target_set;
        target_set.targets = std::move(expanded.targets);
        TargetNormalizer::sort_numeric(target_set.targets);
        if (target_set.empty()) {
            return failure(core::StatusCode::InvalidArgument, make_error(TargetErrorCode::EmptyTargetSet, "target resolution produced no IP targets"));
        }
        return {core::StatusCode::Ok, std::move(target_set), {}};
    } catch (const std::bad_alloc &) {
        return failure(core::StatusCode::MemoryError, make_error(TargetErrorCode::ResourceExhausted, "target normalization allocation failed"));
    } catch (const std::exception &exception) {
        return failure(core::StatusCode::InternalError, make_error(TargetErrorCode::InvalidTarget, std::string("target resolution failed: ") + exception.what()));
    }
}

} // namespace skan::target
