#ifndef SKAN_PACKET_IPV6_EXTENSIONS_HPP
#define SKAN_PACKET_IPV6_EXTENSIONS_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace skan::packet {

enum class IPv6ExtensionParseStatus {
    Complete,
    NoNextHeader,
    Unsupported,
    Malformed,
    LimitExceeded
};

enum class IPv6ExtensionKind : std::uint8_t {
    HopByHop = 0U,
    Routing = 43U,
    Fragment = 44U,
    DestinationOptions = 60U
};

struct IPv6ExtensionHeader final {
    IPv6ExtensionKind kind{};
    std::uint8_t next_header{59U};
    std::size_t offset{0U};
    std::size_t length{0U};
    std::uint16_t fragment_offset{0U};
    bool more_fragments{false};
    std::uint32_t fragment_identification{0U};
};

struct IPv6ExtensionParseResult final {
    IPv6ExtensionParseStatus status{IPv6ExtensionParseStatus::Malformed};
    std::uint8_t terminal_next_header{59U};
    std::size_t consumed_bytes{0U};
    std::vector<IPv6ExtensionHeader> headers;
};

/** Parse only recognized IPv6 extensions within explicit header-count and byte budgets. */
IPv6ExtensionParseResult parse_ipv6_extensions(
    std::span<const std::uint8_t> payload,
    std::uint8_t first_next_header,
    std::size_t max_headers = 8U,
    std::size_t max_bytes = 2048U) noexcept;

} // namespace skan::packet

#endif // SKAN_PACKET_IPV6_EXTENSIONS_HPP
