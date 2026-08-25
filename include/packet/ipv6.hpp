#ifndef SKAN_PACKET_IPV6_HPP
#define SKAN_PACKET_IPV6_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "packet/packet_element.hpp"

namespace skan::packet {

class IPv6 final : public PacketElement {
public:
    static constexpr std::size_t kHeaderSize = 40U;

    IPv6() = default;

    std::uint8_t version() const noexcept;
    std::uint8_t traffic_class() const noexcept;
    std::uint32_t flow_label() const noexcept;
    std::uint16_t payload_length() const noexcept;
    std::uint8_t next_header() const noexcept;
    std::uint8_t hop_limit() const noexcept;
    const std::array<std::uint8_t, 16U> &source_address() const noexcept;
    const std::array<std::uint8_t, 16U> &destination_address() const noexcept;

    void set_version(std::uint8_t value) noexcept;
    void set_traffic_class(std::uint8_t value) noexcept;
    void set_flow_label(std::uint32_t value) noexcept;
    void set_payload_length(std::uint16_t value) noexcept;
    void set_next_header(std::uint8_t value) noexcept;
    void set_hop_limit(std::uint8_t value) noexcept;
    void set_source_address(const std::array<std::uint8_t, 16U> &value) noexcept;
    void set_destination_address(const std::array<std::uint8_t, 16U> &value) noexcept;

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    /** Parse an IPv6 base header and verify the declared payload fits in input. */
    static std::optional<IPv6> parse(std::span<const std::uint8_t> input) noexcept;

private:
    std::uint8_t version_{6U};
    std::uint8_t traffic_class_{0U};
    std::uint32_t flow_label_{0U};
    std::uint16_t payload_length_{0U};
    std::uint8_t next_header_{0U};
    std::uint8_t hop_limit_{64U};
    std::array<std::uint8_t, 16U> source_address_{};
    std::array<std::uint8_t, 16U> destination_address_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_IPV6_HPP
