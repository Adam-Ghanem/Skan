#ifndef SKAN_PACKET_UDP_HPP
#define SKAN_PACKET_UDP_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "packet/packet_element.hpp"

namespace skan::packet {

class UDP final : public PacketElement {
public:
    static constexpr std::size_t kHeaderSize = 8U;

    UDP() = default;

    std::uint16_t source_port() const noexcept;
    std::uint16_t destination_port() const noexcept;
    std::uint16_t length() const noexcept;
    std::uint16_t checksum() const noexcept;
    const std::vector<std::uint8_t> &payload() const noexcept;

    void set_source_port(std::uint16_t value) noexcept;
    void set_destination_port(std::uint16_t value) noexcept;
    void set_payload(std::vector<std::uint8_t> payload);

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    core::StatusCode serialize_with_checksum(
        std::span<std::uint8_t> output,
        std::uint32_t source_address,
        std::uint32_t destination_address) const;

    std::uint16_t checksum_for_ipv4(
        std::uint32_t source_address,
        std::uint32_t destination_address) const;

    core::StatusCode serialize_with_checksum(
        std::span<std::uint8_t> output,
        const std::array<std::uint8_t, 16U> &source_address,
        const std::array<std::uint8_t, 16U> &destination_address) const;

    std::uint16_t checksum_for_ipv6(
        const std::array<std::uint8_t, 16U> &source_address,
        const std::array<std::uint8_t, 16U> &destination_address) const;

    /** Parse a UDP header and payload with exact length and bounds checks. */
    static std::optional<UDP> parse(std::span<const std::uint8_t> input);

private:
    std::uint16_t source_port_{0U};
    std::uint16_t destination_port_{0U};
    std::uint16_t checksum_{0U};
    std::vector<std::uint8_t> payload_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_UDP_HPP
