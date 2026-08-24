#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/udp.hpp"

int main()
{
    skan::packet::UDP udp;
    udp.set_source_port(5353U);
    udp.set_destination_port(53U);
    udp.set_payload({0xDEU, 0xADU, 0xBEU, 0xEFU, 0x01U});

    assert(udp.validate());
    assert(udp.length() == 13U);
    assert(udp.serialized_size() == 13U);
    const std::vector<std::uint8_t> without_checksum = udp.serialize();
    assert(without_checksum.size() == 13U);
    assert(without_checksum[0] == 0x14U);
    assert(without_checksum[1] == 0xE9U);
    assert(without_checksum[4] == 0x00U);
    assert(without_checksum[5] == 0x0DU);

    const std::uint32_t source = 0xC0000201U;
    const std::uint32_t destination = 0xC6336402U;
    std::vector<std::uint8_t> bytes(udp.serialized_size(), 0U);
    assert(udp.serialize_with_checksum(std::span<std::uint8_t>{bytes}, source, destination) == skan::core::StatusCode::Ok);
    assert(udp.checksum_for_ipv4(source, destination) == 0x5FE1U);
    const std::array<std::uint8_t, 13U> expected_checksummed{
        0x14U, 0xE9U, 0x00U, 0x35U, 0x00U, 0x0DU, 0x5FU, 0xE1U,
        0xDEU, 0xADU, 0xBEU, 0xEFU, 0x01U};
    assert(std::equal(bytes.begin(), bytes.end(), expected_checksummed.begin()));
    assert(skan::packet::checksum::ipv4_pseudo_header(source, destination, 17U,
        std::span<const std::uint8_t>{bytes}) == 0U);

    const auto parsed = skan::packet::UDP::parse(std::span<const std::uint8_t>{bytes});
    assert(parsed.has_value());
    assert(parsed->source_port() == 5353U);
    assert(parsed->destination_port() == 53U);
    assert(parsed->length() == 13U);
    assert(parsed->payload() == udp.payload());
    assert(!skan::packet::UDP::parse(std::span<const std::uint8_t>{bytes.data(), 7U}).has_value());

    std::array<std::uint8_t, 13U> bad_length{};
    std::copy(bytes.begin(), bytes.end(), bad_length.begin());
    bad_length[4] = 0x00U;
    bad_length[5] = 0x08U;
    assert(!skan::packet::UDP::parse(std::span<const std::uint8_t>{bad_length}).has_value());

    return 0;
}
