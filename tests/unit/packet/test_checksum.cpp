#include <array>
#include <cassert>
#include <cstdint>

#include "packet/checksum.hpp"

int main()
{
    using skan::packet::checksum::internet;
    using skan::packet::checksum::ipv4_pseudo_header;

    assert(internet(std::span<const std::uint8_t>{}) == 0xFFFFU);

    const std::array<std::uint8_t, 4U> even_bytes{0x00U, 0x01U, 0xF2U, 0x03U};
    const std::array<std::uint8_t, 3U> odd_bytes{0x00U, 0x01U, 0xF2U};
    assert(internet(std::span<const std::uint8_t>{even_bytes}) == 0x0DFBU);
    assert(internet(std::span<const std::uint8_t>{odd_bytes}) == 0x0DFEU);

    const std::array<std::uint8_t, 4U> carry_bytes{0xFFU, 0xFFU, 0xFFU, 0xFFU};
    assert(internet(std::span<const std::uint8_t>{carry_bytes}) == 0x0000U);

    const std::array<std::uint8_t, 20U> ipv4_header{
        0x45U, 0x00U, 0x00U, 0x3CU, 0x1CU, 0x46U, 0x40U, 0x00U,
        0x40U, 0x06U, 0x00U, 0x00U, 0xC0U, 0xA8U, 0x00U, 0x01U,
        0xC0U, 0xA8U, 0x00U, 0xC7U};
    assert(internet(std::span<const std::uint8_t>{ipv4_header}) == 0x9C5DU);

    const std::array<std::uint8_t, 8U> transport{0x00U, 0x50U, 0x00U, 0x35U, 0x00U, 0x08U, 0x00U, 0x00U};
    assert(ipv4_pseudo_header(0xC0000201U, 0xC6336402U, 17U,
                              std::span<const std::uint8_t>{transport}) == 0x1322U);
    return 0;
}
