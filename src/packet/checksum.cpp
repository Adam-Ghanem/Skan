#include "packet/checksum.hpp"

namespace skan::packet::checksum {
namespace {

std::uint32_t add_word(std::uint32_t sum, std::uint16_t word) noexcept
{
    sum += static_cast<std::uint32_t>(word);
    return (sum & 0xFFFFU) + (sum >> 16U);
}

} // namespace

std::uint16_t internet(std::span<const std::uint8_t> bytes) noexcept
{
    std::uint32_t sum = 0U;
    std::size_t offset = 0U;
    while (offset + 1U < bytes.size()) {
        const std::uint16_t word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
            static_cast<std::uint16_t>(bytes[offset + 1U]));
        sum = add_word(sum, word);
        offset += 2U;
    }
    if (offset < bytes.size()) {
        sum = add_word(sum, static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U));
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::uint16_t ipv6_pseudo_header(
    const std::array<std::uint8_t, 16U> &source_address,
    const std::array<std::uint8_t, 16U> &destination_address,
    std::uint8_t next_header,
    std::span<const std::uint8_t> transport_bytes) noexcept
{
    if (transport_bytes.size() > 0xFFFFFFFFULL) {
        return 0U;
    }
    std::uint32_t sum = 0U;
    for (std::size_t index = 0U; index < 16U; index += 2U) {
        sum = add_word(sum, static_cast<std::uint16_t>((static_cast<std::uint16_t>(source_address[index]) << 8U) |
                                                        static_cast<std::uint16_t>(source_address[index + 1U])));
        sum = add_word(sum, static_cast<std::uint16_t>((static_cast<std::uint16_t>(destination_address[index]) << 8U) |
                                                        static_cast<std::uint16_t>(destination_address[index + 1U])));
    }
    sum = add_word(sum, static_cast<std::uint16_t>((transport_bytes.size() >> 16U) & 0xFFFFU));
    sum = add_word(sum, static_cast<std::uint16_t>(transport_bytes.size() & 0xFFFFU));
    sum = add_word(sum, static_cast<std::uint16_t>(next_header));
    for (std::size_t offset = 0U; offset + 1U < transport_bytes.size(); offset += 2U) {
        sum = add_word(sum, static_cast<std::uint16_t>((static_cast<std::uint16_t>(transport_bytes[offset]) << 8U) |
                                                        static_cast<std::uint16_t>(transport_bytes[offset + 1U])));
    }
    if ((transport_bytes.size() & 1U) != 0U) {
        sum = add_word(sum, static_cast<std::uint16_t>(static_cast<std::uint16_t>(transport_bytes.back()) << 8U));
    }
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::uint16_t ipv4_pseudo_header(
    std::uint32_t source_address,
    std::uint32_t destination_address,
    std::uint8_t protocol,
    std::span<const std::uint8_t> transport_bytes) noexcept
{
    if (transport_bytes.size() > 65535U) {
        return 0U;
    }
    std::uint32_t sum = 0U;
    sum = add_word(sum, static_cast<std::uint16_t>(source_address >> 16U));
    sum = add_word(sum, static_cast<std::uint16_t>(source_address & 0xFFFFU));
    sum = add_word(sum, static_cast<std::uint16_t>(destination_address >> 16U));
    sum = add_word(sum, static_cast<std::uint16_t>(destination_address & 0xFFFFU));
    sum = add_word(sum, static_cast<std::uint16_t>(protocol));
    sum = add_word(sum, static_cast<std::uint16_t>(transport_bytes.size()));

    std::size_t offset = 0U;
    while (offset + 1U < transport_bytes.size()) {
        const std::uint16_t word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(transport_bytes[offset]) << 8U) |
            static_cast<std::uint16_t>(transport_bytes[offset + 1U]));
        sum = add_word(sum, word);
        offset += 2U;
    }
    if (offset < transport_bytes.size()) {
        sum = add_word(sum, static_cast<std::uint16_t>(static_cast<std::uint16_t>(transport_bytes[offset]) << 8U));
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

} // namespace skan::packet::checksum
