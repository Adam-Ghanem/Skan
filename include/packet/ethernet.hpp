#ifndef SKAN_PACKET_ETHERNET_HPP
#define SKAN_PACKET_ETHERNET_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "packet/packet_element.hpp"

namespace skan::packet {

class Ethernet final : public PacketElement {
public:
    static constexpr std::size_t kHeaderSize = 14U;
    using MacAddress = std::array<std::uint8_t, 6U>;

    Ethernet() = default;
    Ethernet(MacAddress destination, MacAddress source, std::uint16_t ether_type) noexcept;

    const MacAddress &destination() const noexcept;
    const MacAddress &source() const noexcept;
    std::uint16_t ether_type() const noexcept;

    void set_destination(MacAddress destination) noexcept;
    void set_source(MacAddress source) noexcept;
    void set_ether_type(std::uint16_t ether_type) noexcept;

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    /** Parse exactly one Ethernet II header without reading beyond input. */
    static std::optional<Ethernet> parse(std::span<const std::uint8_t> input) noexcept;

private:
    MacAddress destination_{};
    MacAddress source_{};
    std::uint16_t ether_type_{0U};
};

} // namespace skan::packet

#endif // SKAN_PACKET_ETHERNET_HPP
