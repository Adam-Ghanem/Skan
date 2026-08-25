#ifndef SKAN_PACKET_ICMP_HPP
#define SKAN_PACKET_ICMP_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "packet/packet_element.hpp"

namespace skan::packet {

enum class IcmpType : std::uint8_t {
    EchoReply = 0U,
    DestinationUnreachable = 3U,
    EchoRequest = 8U
};

class ICMP final : public PacketElement {
public:
    static constexpr std::size_t kHeaderSize = 8U;

    ICMP() = default;
    explicit ICMP(IcmpType type) noexcept;

    IcmpType type() const noexcept;
    std::uint8_t code() const noexcept;
    std::uint16_t identifier() const noexcept;
    std::uint16_t sequence() const noexcept;
    std::uint16_t checksum() const noexcept;
    const std::vector<std::uint8_t> &payload() const noexcept;

    void set_type(IcmpType type) noexcept;
    void set_code(std::uint8_t value) noexcept;
    void set_identifier(std::uint16_t value) noexcept;
    void set_sequence(std::uint16_t value) noexcept;
    void set_payload(std::vector<std::uint8_t> payload);

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    /** Parse an ICMPv4 Echo message with bounds checks. */
    static std::optional<ICMP> parse(std::span<const std::uint8_t> input);

private:
    IcmpType type_{IcmpType::EchoRequest};
    std::uint8_t code_{0U};
    std::uint16_t identifier_{0U};
    std::uint16_t sequence_{0U};
    std::uint16_t checksum_{0U};
    std::vector<std::uint8_t> payload_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_ICMP_HPP
