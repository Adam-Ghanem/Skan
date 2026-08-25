#ifndef SKAN_PACKET_ICMPV6_HPP
#define SKAN_PACKET_ICMPV6_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "packet/packet_element.hpp"

namespace skan::packet {

enum class Icmpv6Type : std::uint8_t {
    DestinationUnreachable = 1U,
    PacketTooBig = 2U,
    TimeExceeded = 3U,
    ParameterProblem = 4U,
    EchoRequest = 128U,
    EchoReply = 129U,
    NeighborSolicitation = 135U,
    NeighborAdvertisement = 136U
};

/**
 * Bounded ICMPv6 message model. The four-byte body is represented as rest_word;
 * Echo messages expose the conventional identifier/sequence fields through helpers.
 * Checksum validation requires the IPv6 pseudo-header and is therefore explicit.
 */
class ICMPv6 final : public PacketElement {
public:
    static constexpr std::size_t kHeaderSize = 8U;

    ICMPv6() = default;
    explicit ICMPv6(Icmpv6Type type) noexcept;

    Icmpv6Type type() const noexcept;
    std::uint8_t code() const noexcept;
    std::uint16_t checksum() const noexcept;
    std::uint32_t rest_word() const noexcept;
    std::uint16_t identifier() const noexcept;
    std::uint16_t sequence() const noexcept;
    const std::vector<std::uint8_t> &payload() const noexcept;

    void set_type(Icmpv6Type type) noexcept;
    void set_code(std::uint8_t value) noexcept;
    void set_rest_word(std::uint32_t value) noexcept;
    void set_identifier(std::uint16_t value) noexcept;
    void set_sequence(std::uint16_t value) noexcept;
    void set_payload(std::vector<std::uint8_t> payload);

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    core::StatusCode serialize_with_checksum(
        std::span<std::uint8_t> output,
        const std::array<std::uint8_t, 16U> &source_address,
        const std::array<std::uint8_t, 16U> &destination_address) const noexcept;
    bool validate() const noexcept override;

    /** Parse a structurally recognized ICMPv6 message without reading beyond input. */
    static std::optional<ICMPv6> parse(std::span<const std::uint8_t> input) noexcept;

private:
    static bool is_supported_type(std::uint8_t value) noexcept;

    Icmpv6Type type_{Icmpv6Type::EchoRequest};
    std::uint8_t code_{0U};
    std::uint16_t checksum_{0U};
    std::uint32_t rest_word_{0U};
    std::vector<std::uint8_t> payload_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_ICMPV6_HPP
