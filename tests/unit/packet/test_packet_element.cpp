#include <array>
#include <cassert>
#include <cstdint>
#include <span>

#include "packet/ethernet.hpp"
#include "packet/packet_element.hpp"

int main()
{
    const skan::packet::Ethernet::MacAddress address{0U, 1U, 2U, 3U, 4U, 5U};
    const skan::packet::Ethernet ethernet(address, address, 0x0800U);
    assert(ethernet.serialized_size() == 14U);

    const skan::packet::PacketElement &element = ethernet;
    const std::vector<std::uint8_t> owned = element.serialize();
    assert(owned.size() == element.serialized_size());
    assert(owned[12] == 0x08U && owned[13] == 0x00U);

    std::array<std::uint8_t, 14U> output{};
    assert(element.serialize(std::span<std::uint8_t>{output}) == skan::core::StatusCode::Ok);
    assert(output[0] == 0U && output[5] == 5U);

    std::array<std::uint8_t, 13U> too_small{};
    assert(element.serialize(std::span<std::uint8_t>{too_small}) == skan::core::StatusCode::InvalidArgument);
    return 0;
}
