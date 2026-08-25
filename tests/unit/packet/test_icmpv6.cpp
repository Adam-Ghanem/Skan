#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/icmpv6.hpp"

int main()
{
    const std::array<std::uint8_t, 16U> source{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
    const std::array<std::uint8_t, 16U> destination{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};

    skan::packet::ICMPv6 echo(skan::packet::Icmpv6Type::EchoRequest);
    echo.set_identifier(0x1234U);
    echo.set_sequence(0x0042U);
    echo.set_payload({0x70U, 0x69U, 0x6EU, 0x67U});
    assert(echo.validate());

    std::vector<std::uint8_t> bytes(echo.serialized_size(), 0U);
    assert(echo.serialize_with_checksum(std::span<std::uint8_t>{bytes}, source, destination) == skan::core::StatusCode::Ok);
    assert(bytes[0] == 128U && bytes[1] == 0U);
    assert(bytes[4] == 0x12U && bytes[5] == 0x34U && bytes[6] == 0U && bytes[7] == 0x42U);
    assert(skan::packet::checksum::ipv6_pseudo_header(
        source, destination, 58U, std::span<const std::uint8_t>{bytes}) == 0U);

    const auto parsed = skan::packet::ICMPv6::parse(std::span<const std::uint8_t>{bytes});
    assert(parsed.has_value());
    assert(parsed->type() == skan::packet::Icmpv6Type::EchoRequest);
    assert(parsed->identifier() == 0x1234U && parsed->sequence() == 0x0042U);
    assert(parsed->payload() == std::vector<std::uint8_t>({0x70U, 0x69U, 0x6EU, 0x67U}));

    std::vector<std::uint8_t> truncated(bytes.begin(), bytes.begin() + 7);
    assert(!skan::packet::ICMPv6::parse(std::span<const std::uint8_t>{truncated}).has_value());
    std::vector<std::uint8_t> unknown = bytes;
    unknown[0] = 200U;
    assert(!skan::packet::ICMPv6::parse(std::span<const std::uint8_t>{unknown}).has_value());

    echo.set_code(1U);
    assert(!echo.validate());
    skan::packet::ICMPv6 unreachable(skan::packet::Icmpv6Type::DestinationUnreachable);
    unreachable.set_code(1U);
    assert(unreachable.validate());
    return 0;
}
