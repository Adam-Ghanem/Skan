#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/icmp.hpp"
#include "packet/packet.hpp"
#include "packet/ipv4.hpp"
#include "packet/udp.hpp"

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

    skan::packet::UDP embedded_udp;
    embedded_udp.set_source_port(40000U);
    embedded_udp.set_destination_port(53U);
    embedded_udp.set_payload({0x01U, 0x02U});
    skan::packet::IPv4 embedded_ipv4;
    embedded_ipv4.set_protocol(17U);
    embedded_ipv4.set_source_address(0xC0000201U);
    embedded_ipv4.set_destination_address(0xC000020AU);
    skan::packet::Packet embedded_packet;
    embedded_packet.set_ipv4(embedded_ipv4);
    embedded_packet.set_udp(embedded_udp);
    const std::vector<std::uint8_t> embedded_bytes = embedded_packet.serialize();
    assert(embedded_bytes.size() == 30U);
    skan::packet::ICMP unreachable(skan::packet::IcmpType::DestinationUnreachable);
    unreachable.set_code(3U);
    unreachable.set_payload(embedded_bytes);
    const std::vector<std::uint8_t> unreachable_bytes = unreachable.serialize();
    assert(unreachable.validate());
    const auto parsed_unreachable = skan::packet::ICMP::parse(std::span<const std::uint8_t>{unreachable_bytes});
    assert(parsed_unreachable.has_value());
    assert(parsed_unreachable->type() == skan::packet::IcmpType::DestinationUnreachable);
    assert(parsed_unreachable->code() == 3U);
    assert(parsed_unreachable->payload() == embedded_bytes);
    for (std::size_t length = 0U; length < unreachable_bytes.size(); ++length) {
        assert(!skan::packet::ICMP::parse(
                    std::span<const std::uint8_t>{unreachable_bytes}.first(length)).has_value());
    }

    skan::packet::ICMP reply(skan::packet::IcmpType::EchoReply);
    assert(reply.validate());
    const std::vector<std::uint8_t> reply_bytes = reply.serialize();
    assert(reply_bytes.size() == skan::packet::ICMP::kHeaderSize);
    assert(reply_bytes[0] == 0x00U);
    return 0;
}
