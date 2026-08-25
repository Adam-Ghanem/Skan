#ifndef SKAN_PACKET_IPV6_QUOTE_HPP
#define SKAN_PACKET_IPV6_QUOTE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "packet/ipv6.hpp"
#include "packet/ipv6_extensions.hpp"

namespace skan::packet {

struct IPv6UdpQuote final {
    IPv6 ip;
    IPv6ExtensionParseResult extensions;
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    std::uint16_t length{0U};
    std::uint16_t checksum{0U};
};

/**
 * Parse the bounded IPv6 packet quoted by an ICMPv6 error and extract its UDP
 * identity. The quoted packet may be truncated after the UDP header, as
 * permitted by ICMPv6, but all IPv6 and extension bounds remain strict.
 */
std::optional<IPv6UdpQuote> parse_ipv6_udp_quote(
    std::span<const std::uint8_t> input,
    std::size_t max_headers = 8U,
    std::size_t max_bytes = 2048U) noexcept;

} // namespace skan::packet

#endif // SKAN_PACKET_IPV6_QUOTE_HPP
