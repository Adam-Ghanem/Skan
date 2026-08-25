#include "core/types.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cstddef>
#include <functional>
#include <limits>
#include <net/if.h>
#include <netinet/in.h>

static_assert(std::numeric_limits<std::uint16_t>::max() >= 65535U,
              "port numbers must support the full 16-bit range");

namespace skan::core {
namespace {

bool valid_scope_token(std::string_view scope) noexcept
{
    if (scope.empty() || scope.size() >= IFNAMSIZ) {
        return false;
    }
    for (const unsigned char character : scope) {
        if (character < 0x21U || character > 0x7EU || character == '%' || character == ',' || character == '/') {
            return false;
        }
    }
    return true;
}

} // namespace

IpAddress IpAddress::from_ipv4(std::uint32_t address) noexcept
{
    IpAddress result;
    result.family = AddressFamily::IPv4;
    result.bytes[0] = static_cast<std::uint8_t>((address >> 24U) & 0xFFU);
    result.bytes[1] = static_cast<std::uint8_t>((address >> 16U) & 0xFFU);
    result.bytes[2] = static_cast<std::uint8_t>((address >> 8U) & 0xFFU);
    result.bytes[3] = static_cast<std::uint8_t>(address & 0xFFU);
    return result;
}

IpAddress IpAddress::from_ipv6(const std::array<std::uint8_t, 16U> &address) noexcept
{
    IpAddress result;
    result.family = AddressFamily::IPv6;
    result.bytes = address;
    return result;
}

std::string IpAddress::to_string() const
{
    char buffer[INET6_ADDRSTRLEN]{};
    if (is_ipv4()) {
        in_addr address{};
        address.s_addr = htonl((static_cast<std::uint32_t>(bytes[0]) << 24U) |
                               (static_cast<std::uint32_t>(bytes[1]) << 16U) |
                               (static_cast<std::uint32_t>(bytes[2]) << 8U) |
                               static_cast<std::uint32_t>(bytes[3]));
        if (::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) != nullptr) {
            return buffer;
        }
    } else if (is_ipv6()) {
        in6_addr address{};
        std::copy(bytes.begin(), bytes.end(), address.s6_addr);
        if (::inet_ntop(AF_INET6, &address, buffer, sizeof(buffer)) != nullptr) {
            std::string result(buffer);
            if (has_scope()) {
                result.push_back('%');
                result += *scope;
            }
            return result;
        }
    }
    return {};
}

bool operator<(const IpAddress &left, const IpAddress &right) noexcept
{
    if (left.family != right.family) {
        return static_cast<unsigned int>(left.family) < static_cast<unsigned int>(right.family);
    }
    const std::size_t length = left.is_ipv4() ? 4U : 16U;
    const auto left_end = left.bytes.begin() + static_cast<std::ptrdiff_t>(length);
    const auto right_end = right.bytes.begin() + static_cast<std::ptrdiff_t>(length);
    if (!std::equal(left.bytes.begin(), left_end, right.bytes.begin())) {
        return std::lexicographical_compare(left.bytes.begin(), left_end, right.bytes.begin(), right_end);
    }
    if (left.scope.has_value() != right.scope.has_value()) {
        return !left.scope.has_value();
    }
    if (left.scope.has_value() && right.scope.has_value()) {
        return *left.scope < *right.scope;
    }
    return false;
}

std::size_t IpAddressHash::operator()(const IpAddress &address) const noexcept
{
    std::size_t hash = static_cast<std::size_t>(address.family);
    const std::size_t length = address.is_ipv4() ? 4U : address.is_ipv6() ? 16U : 0U;
    for (std::size_t index = 0U; index < length; ++index) {
        hash ^= static_cast<std::size_t>(address.bytes[index]) + static_cast<std::size_t>(0x9E3779B9U) +
                (hash << 6U) + (hash >> 2U);
    }
    if (address.has_scope()) {
        for (const unsigned char character : *address.scope) {
            hash ^= static_cast<std::size_t>(character) + static_cast<std::size_t>(0x9E3779B9U) +
                    (hash << 6U) + (hash >> 2U);
        }
    }
    return hash;
}

std::optional<IpAddress> parse_ip_address(std::string_view text) noexcept
{
    if (text.empty()) {
        return std::nullopt;
    }
    const std::size_t scope_separator = text.find('%');
    std::string_view address_text = text;
    std::string_view scope_text;
    if (scope_separator != std::string_view::npos) {
        if (text.find('%', scope_separator + 1U) != std::string_view::npos) {
            return std::nullopt;
        }
        address_text = text.substr(0U, scope_separator);
        scope_text = text.substr(scope_separator + 1U);
        if (!valid_scope_token(scope_text)) {
            return std::nullopt;
        }
        bool numeric_scope = true;
        for (const char character : scope_text) {
            if (character < '0' || character > '9') {
                numeric_scope = false;
                break;
            }
        }
        if (numeric_scope) {
            std::uint32_t numeric_value = 0U;
            const char *scope_first = scope_text.data();
            const char *scope_last = scope_text.data() + static_cast<std::ptrdiff_t>(scope_text.size());
            const auto parsed_scope = std::from_chars(scope_first, scope_last, numeric_value, 10);
            if (parsed_scope.ec != std::errc{} || parsed_scope.ptr != scope_last || numeric_value == 0U) {
                return std::nullopt;
            }
        }
    }
    if (address_text.empty()) {
        return std::nullopt;
    }
    try {
        const std::string value(address_text);
        if (scope_separator == std::string_view::npos) {
            in_addr ipv4{};
            if (::inet_pton(AF_INET, value.c_str(), &ipv4) == 1) {
                return IpAddress::from_ipv4(ntohl(ipv4.s_addr));
            }
        }
        in6_addr ipv6{};
        if (::inet_pton(AF_INET6, value.c_str(), &ipv6) != 1) {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16U> bytes{};
        std::copy(std::begin(ipv6.s6_addr), std::end(ipv6.s6_addr), bytes.begin());
        IpAddress result = IpAddress::from_ipv6(bytes);
        if (!scope_text.empty()) {
            result.scope = std::string(scope_text);
        }
        return result;
    } catch (const std::bad_alloc &) {
        return std::nullopt;
    }
}

std::optional<std::uint32_t> ipv6_scope_id(const IpAddress &address) noexcept
{
    if (!address.is_ipv6()) {
        return std::nullopt;
    }
    if (!address.has_scope()) {
        return 0U;
    }
    const std::string &scope = *address.scope;
    bool numeric = true;
    for (const char character : scope) {
        if (character < '0' || character > '9') {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        std::uint32_t value = 0U;
        const char *first = scope.data();
        const char *last = scope.data() + static_cast<std::ptrdiff_t>(scope.size());
        const auto parsed = std::from_chars(first, last, value, 10);
        if (parsed.ec == std::errc{} && parsed.ptr == last && value != 0U) {
            return value;
        }
        return std::nullopt;
    }
    const unsigned int interface_index = ::if_nametoindex(scope.c_str());
    if (interface_index == 0U) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(interface_index);
}

const char *address_family_name(AddressFamily family) noexcept
{
    switch (family) {
    case AddressFamily::IPv4:
        return "ipv4";
    case AddressFamily::IPv6:
        return "ipv6";
    case AddressFamily::Unknown:
        return "unknown";
    }
    return "unknown";
}

} // namespace skan::core
