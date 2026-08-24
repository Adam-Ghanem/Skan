#ifndef SKAN_PACKET_IPV4_HPP
#define SKAN_PACKET_IPV4_HPP

#include <cstdint>
#include <optional>
#include <span>

#include "packet/packet_element.hpp"

namespace skan::packet {

class IPv4 final : public PacketElement {
public:
    static constexpr std::size_t kMinimumHeaderSize = 20U;

    IPv4() = default;

    std::uint8_t version() const noexcept;
    std::uint8_t ihl() const noexcept;
    std::uint8_t dscp_ecn() const noexcept;
    std::uint16_t total_length() const noexcept;
    std::uint16_t identification() const noexcept;
    std::uint16_t flags_fragment_offset() const noexcept;
    std::uint8_t ttl() const noexcept;
    std::uint8_t protocol() const noexcept;
    std::uint16_t header_checksum() const noexcept;
    std::uint32_t source_address() const noexcept;
    std::uint32_t destination_address() const noexcept;

    void set_version(std::uint8_t value) noexcept;
    void set_ihl(std::uint8_t value) noexcept;
    void set_dscp_ecn(std::uint8_t value) noexcept;
    void set_total_length(std::uint16_t value) noexcept;
    void set_identification(std::uint16_t value) noexcept;
    void set_flags_fragment_offset(std::uint16_t value) noexcept;
    void set_ttl(std::uint8_t value) noexcept;
    void set_protocol(std::uint8_t value) noexcept;
    void set_source_address(std::uint32_t value) noexcept;
    void set_destination_address(std::uint32_t value) noexcept;

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    /** Parse an IPv4 header, validating version, IHL, and supplied bounds. */
    static std::optional<IPv4> parse(std::span<const std::uint8_t> input) noexcept;

private:
    std::uint8_t version_{4U};
    std::uint8_t ihl_{5U};
    std::uint8_t dscp_ecn_{0U};
    std::uint16_t total_length_{kMinimumHeaderSize};
    std::uint16_t identification_{0U};
    std::uint16_t flags_fragment_offset_{0U};
    std::uint8_t ttl_{64U};
    std::uint8_t protocol_{0U};
    std::uint16_t header_checksum_{0U};
    std::uint32_t source_address_{0U};
    std::uint32_t destination_address_{0U};
};

} // namespace skan::packet

#endif // SKAN_PACKET_IPV4_HPP
