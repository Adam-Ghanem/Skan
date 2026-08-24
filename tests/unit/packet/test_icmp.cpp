#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/icmp.hpp"

int main()
{
    skan::packet::ICMP echo(skan::packet::IcmpType::EchoRequest);
    echo.set_identifier(0x1234U);
    echo.set_sequence(0x0001U);
    echo.set_payload({0x70U, 0x69U, 0x6EU, 0x67U});

    assert(echo.validate());
    assert(echo.serialized_size() == 12U);
    const std::vector<std::uint8_t> bytes = echo.serialize();
    const std::array<std::uint8_t, 12U> expected{
        0x08U, 0x00U, 0x06U, 0xFAU, 0x12U, 0x34U, 0x00U, 0x01U,
        0x70U, 0x69U, 0x6EU, 0x67U};
    assert(std::equal(bytes.begin(), bytes.end(), expected.begin()));
    assert(skan::packet::checksum::internet(std::span<const std::uint8_t>{bytes}) == 0U);

    const auto parsed = skan::packet::ICMP::parse(std::span<const std::uint8_t>{bytes});
    assert(parsed.has_value());
    assert(parsed->type() == skan::packet::IcmpType::EchoRequest);
    assert(parsed->code() == 0U);
    assert(parsed->identifier() == 0x1234U);
    assert(parsed->sequence() == 1U);
    assert(parsed->payload() == echo.payload());
    assert(!skan::packet::ICMP::parse(std::span<const std::uint8_t>{bytes.data(), 7U}).has_value());

    std::array<std::uint8_t, 12U> bad_checksum = expected;
    bad_checksum[2] ^= 0x01U;
    assert(!skan::packet::ICMP::parse(std::span<const std::uint8_t>{bad_checksum}).has_value());

    skan::packet::ICMP reply(skan::packet::IcmpType::EchoReply);
    assert(reply.validate());
    const std::vector<std::uint8_t> reply_bytes = reply.serialize();
    assert(reply_bytes.size() == skan::packet::ICMP::kHeaderSize);
    assert(reply_bytes[0] == 0x00U);
    return 0;
}
