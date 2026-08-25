#include "packet/ipv6_extensions.hpp"

#include <limits>

namespace skan::packet {
namespace {

bool is_supported_extension(std::uint8_t next_header) noexcept
{
    return next_header == 0U || next_header == 43U || next_header == 44U || next_header == 60U;
}

bool is_terminal_protocol(std::uint8_t next_header) noexcept
{
    return next_header == 6U || next_header == 17U || next_header == 58U || next_header == 59U;
}

} // namespace

IPv6ExtensionParseResult parse_ipv6_extensions(
    std::span<const std::uint8_t> payload,
    std::uint8_t first_next_header,
    std::size_t max_headers,
    std::size_t max_bytes) noexcept
{
    IPv6ExtensionParseResult result;
    result.terminal_next_header = first_next_header;
    if (max_headers == 0U || max_bytes == 0U) {
        result.status = IPv6ExtensionParseStatus::LimitExceeded;
        return result;
    }

    std::size_t offset = 0U;
    std::uint8_t next_header = first_next_header;
    while (is_supported_extension(next_header)) {
        if (result.headers.size() >= max_headers || offset >= max_bytes) {
            result.status = IPv6ExtensionParseStatus::LimitExceeded;
            result.consumed_bytes = offset;
            return result;
        }
        const std::size_t remaining_budget = max_bytes - offset;
        const std::size_t available = payload.size() - offset;
        if (available < 2U || remaining_budget < 2U) {
            result.status = IPv6ExtensionParseStatus::Malformed;
            result.consumed_bytes = offset;
            return result;
        }

        const std::uint8_t extension_next = payload[offset];
        std::size_t length = 0U;
        if (next_header == 44U) {
            length = 8U;
        } else {
            length = (static_cast<std::size_t>(payload[offset + 1U]) + 1U) * 8U;
            if (length < 8U) {
                result.status = IPv6ExtensionParseStatus::Malformed;
                result.consumed_bytes = offset;
                return result;
            }
        }
        if (length > available || length > remaining_budget) {
            result.status = length > remaining_budget ? IPv6ExtensionParseStatus::LimitExceeded : IPv6ExtensionParseStatus::Malformed;
            result.consumed_bytes = offset;
            return result;
        }

        IPv6ExtensionHeader header;
        header.kind = static_cast<IPv6ExtensionKind>(next_header);
        header.next_header = extension_next;
        header.offset = offset;
        header.length = length;
        if (next_header == 44U) {
            const std::uint16_t fragment = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(payload[offset + 2U]) << 8U) |
                static_cast<std::uint16_t>(payload[offset + 3U]));
            header.fragment_offset = static_cast<std::uint16_t>((fragment >> 3U) & 0x1FFFU);
            header.more_fragments = (fragment & 0x0001U) != 0U;
            header.fragment_identification =
                (static_cast<std::uint32_t>(payload[offset + 4U]) << 24U) |
                (static_cast<std::uint32_t>(payload[offset + 5U]) << 16U) |
                (static_cast<std::uint32_t>(payload[offset + 6U]) << 8U) |
                static_cast<std::uint32_t>(payload[offset + 7U]);
        }
        result.headers.push_back(header);
        offset += length;
        next_header = extension_next;
    }

    result.terminal_next_header = next_header;
    result.consumed_bytes = offset;
    if (next_header == 59U) {
        result.status = IPv6ExtensionParseStatus::NoNextHeader;
    } else if (is_terminal_protocol(next_header)) {
        result.status = IPv6ExtensionParseStatus::Complete;
    } else {
        result.status = IPv6ExtensionParseStatus::Unsupported;
    }
    return result;
}

} // namespace skan::packet
