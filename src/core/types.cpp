#include "core/types.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <functional>
#include <limits>
#include <netinet/in.h>

static_assert(std::numeric_limits<std::uint16_t>::max() >= 65535U,
              "port numbers must support the full 16-bit range");

namespace skan::core {

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
            return buffer;
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
    return std::lexicographical_compare(left.bytes.begin(), left.bytes.begin() + static_cast<std::ptrdiff_t>(length),
                                        right.bytes.begin(), right.bytes.begin() + static_cast<std::ptrdiff_t>(length));
}

std::size_t IpAddressHash::operator()(const IpAddress &address) const noexcept
{
    std::size_t hash = static_cast<std::size_t>(address.family);
    const std::size_t length = address.is_ipv4() ? 4U : address.is_ipv6() ? 16U : 0U;
    for (std::size_t index = 0U; index < length; ++index) {
        hash ^= static_cast<std::size_t>(address.bytes[index]) + static_cast<std::size_t>(0x9E3779B9U) +
                (hash << 6U) + (hash >> 2U);
    }
    return hash;
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
