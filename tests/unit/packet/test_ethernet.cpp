#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/ethernet.hpp"

int main()
{
    const skan::packet::Ethernet::MacAddress destination{0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    const skan::packet::Ethernet::MacAddress source{0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU};
    const skan::packet::Ethernet ethernet(destination, source, 0x0800U);

    assert(ethernet.serialized_size() == 14U);
    assert(ethernet.validate());
    const std::vector<std::uint8_t> bytes = ethernet.serialize();
    const std::array<std::uint8_t, 14U> expected{
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU,
        0x08U, 0x00U};
    assert(bytes.size() == expected.size());
    assert(std::equal(bytes.begin(), bytes.end(), expected.begin()));

    const auto parsed = skan::packet::Ethernet::parse(std::span<const std::uint8_t>{bytes});
    assert(parsed.has_value());
    assert(parsed->destination() == destination);
    assert(parsed->source() == source);
    assert(parsed->ether_type() == 0x0800U);
    assert(!skan::packet::Ethernet::parse(std::span<const std::uint8_t>{bytes.data(), 13U}).has_value());

    skan::packet::Ethernet invalid;
    assert(!invalid.validate());
    std::array<std::uint8_t, 14U> output{};
    assert(invalid.serialize(std::span<std::uint8_t>{output}) == skan::core::StatusCode::InvalidArgument);
    return 0;
}
