#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/ipv4.hpp"

int main()
{
    skan::packet::IPv4 ipv4;
    assert(ipv4.version() == 4U);
    assert(ipv4.ihl() == 5U);
    assert(ipv4.ttl() == 64U);
    assert(ipv4.serialized_size() == 20U);
    assert(ipv4.validate());

    ipv4.set_dscp_ecn(0U);
    ipv4.set_total_length(60U);
    ipv4.set_identification(0x1C46U);
    ipv4.set_flags_fragment_offset(0x4000U);
    ipv4.set_ttl(64U);
    ipv4.set_protocol(6U);
    ipv4.set_source_address(0xC0A80001U);
    ipv4.set_destination_address(0xC0A800C7U);

    const std::vector<std::uint8_t> bytes = ipv4.serialize();
    const std::array<std::uint8_t, 20U> expected{
        0x45U, 0x00U, 0x00U, 0x3CU, 0x1CU, 0x46U, 0x40U, 0x00U,
        0x40U, 0x06U, 0x9CU, 0x5DU, 0xC0U, 0xA8U, 0x00U, 0x01U,
        0xC0U, 0xA8U, 0x00U, 0xC7U};
    assert(bytes.size() == expected.size());
    assert(std::equal(bytes.begin(), bytes.end(), expected.begin()));
    assert(skan::packet::checksum::internet(std::span<const std::uint8_t>{bytes}) == 0U);

    std::vector<std::uint8_t> complete_packet(60U, 0U);
    std::copy(bytes.begin(), bytes.end(), complete_packet.begin());
    const auto parsed = skan::packet::IPv4::parse(std::span<const std::uint8_t>{complete_packet});
    assert(parsed.has_value());
    assert(parsed->total_length() == 60U);
    assert(parsed->identification() == 0x1C46U);
    assert(parsed->flags_fragment_offset() == 0x4000U);
    assert(parsed->protocol() == 6U);
    assert(parsed->source_address() == 0xC0A80001U);
    assert(parsed->destination_address() == 0xC0A800C7U);
    assert(!skan::packet::IPv4::parse(std::span<const std::uint8_t>{bytes.data(), 19U}).has_value());

    std::array<std::uint8_t, 20U> bad_version = expected;
    bad_version[0] = 0x65U;
    assert(!skan::packet::IPv4::parse(std::span<const std::uint8_t>{bad_version}).has_value());
    std::array<std::uint8_t, 20U> bad_checksum = expected;
    bad_checksum[10] ^= 0x01U;
    assert(!skan::packet::IPv4::parse(std::span<const std::uint8_t>{bad_checksum}).has_value());

    ipv4.set_ihl(4U);
    assert(!ipv4.validate());
    return 0;
}
