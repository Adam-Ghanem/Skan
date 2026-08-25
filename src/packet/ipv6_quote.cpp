#include "packet/ipv6_quote.hpp"

#include <algorithm>

#include "packet/packet_element.hpp"

namespace skan::packet {

std::optional<IPv6UdpQuote> parse_ipv6_udp_quote(
    std::span<const std::uint8_t> input,
    std::size_t max_headers,
    std::size_t max_bytes) noexcept
{
    if (max_headers == 0U || max_bytes < IPv6::kHeaderSize + 8U || input.size() < IPv6::kHeaderSize + 8U) {
        return std::nullopt;
    }
    const std::size_t bounded_size = std::min(input.size(), max_bytes);
    if (bounded_size < IPv6::kHeaderSize + 8U) {
        return std::nullopt;
    }
    const std::span<const std::uint8_t> bounded = input.first(bounded_size);
    if ((bounded[0] >> 4U) != 6U) {
        return std::nullopt;
    }

    IPv6 ip;
    ip.set_version(static_cast<std::uint8_t>(bounded[0] >> 4U));
    ip.set_traffic_class(static_cast<std::uint8_t>(((bounded[0] & 0x0FU) << 4U) | (bounded[1] >> 4U)));
    ip.set_flow_label((static_cast<std::uint32_t>(bounded[1] & 0x0FU) << 16U) |
                      (static_cast<std::uint32_t>(bounded[2]) << 8U) |
                      static_cast<std::uint32_t>(bounded[3]));
    ip.set_payload_length(wire::read_u16(bounded, 4U));
    ip.set_next_header(bounded[6]);
    ip.set_hop_limit(bounded[7]);
    std::array<std::uint8_t, 16U> source{};
    std::array<std::uint8_t, 16U> destination{};
    for (std::size_t index = 0U; index < source.size(); ++index) {
        source[index] = bounded[8U + index];
        destination[index] = bounded[24U + index];
    }
    ip.set_source_address(source);
    ip.set_destination_address(destination);
    if (!ip.validate()) {
        return std::nullopt;
    }

    const std::span<const std::uint8_t> payload = bounded.subspan(IPv6::kHeaderSize);
    const IPv6ExtensionParseResult extensions = parse_ipv6_extensions(payload, ip.next_header(), max_headers,
                                                                       std::min(max_bytes, payload.size()));
    if (extensions.status != IPv6ExtensionParseStatus::Complete ||
        extensions.terminal_next_header != 17U ||
        extensions.consumed_bytes > payload.size() ||
        static_cast<std::size_t>(ip.payload_length()) < extensions.consumed_bytes + 8U) {
        return std::nullopt;
    }
    for (const IPv6ExtensionHeader &header : extensions.headers) {
        if (header.kind == IPv6ExtensionKind::Fragment && header.fragment_offset != 0U) {
            return std::nullopt;
        }
    }

    const std::span<const std::uint8_t> udp = payload.subspan(extensions.consumed_bytes);
    if (udp.size() < 8U) {
        return std::nullopt;
    }
    const std::uint16_t length = wire::read_u16(udp, 4U);
    if (length < 8U) {
        return std::nullopt;
    }
    IPv6UdpQuote quote;
    quote.ip = ip;
    quote.extensions = extensions;
    quote.source_port = wire::read_u16(udp, 0U);
    quote.destination_port = wire::read_u16(udp, 2U);
    quote.length = length;
    quote.checksum = wire::read_u16(udp, 6U);
    return quote;
}

} // namespace skan::packet
