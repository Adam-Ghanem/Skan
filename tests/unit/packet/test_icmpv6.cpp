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

    skan::packet::ICMPv6 solicitation(skan::packet::Icmpv6Type::NeighborSolicitation);
    solicitation.set_payload({0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x00U,
                              0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x09U,
                              0x01U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U});
    assert(solicitation.validate());
    const auto neighbor_target = solicitation.neighbor_target();
    assert(neighbor_target.has_value() && (*neighbor_target)[15] == 0x09U);
    const auto neighbor_options = solicitation.neighbor_options();
    assert(neighbor_options.size() == 1U && neighbor_options.front().type == 1U &&
           neighbor_options.front().mac[0] == 0x02U && neighbor_options.front().mac[5] == 0x07U);
    auto malformed_option = solicitation;
    malformed_option.set_payload({0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x00U,
                                  0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x09U,
                                  0x01U, 0x00U});
    assert(!malformed_option.validate());
    auto multicast_target = solicitation;
    multicast_target.set_payload({0xFFU, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                                  0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
                                  0x01U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U});
    assert(!multicast_target.validate());

    const std::array<std::uint8_t, 6U> mac{0x02U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU};
    const auto built_ns = skan::packet::ICMPv6::make_neighbor_solicitation(source, mac);
    assert(built_ns.has_value() && built_ns->validate() && built_ns->neighbor_options().size() == 1U);
    assert(built_ns->neighbor_options().front().type == 1U && built_ns->neighbor_options().front().mac == mac);
    const auto built_na = skan::packet::ICMPv6::make_neighbor_advertisement(source, mac);
    assert(built_na.has_value() && built_na->validate() && built_na->neighbor_options().size() == 1U);
    assert(built_na->neighbor_options().front().type == 2U && built_na->neighbor_options().front().mac == mac);
    const auto solicited = skan::packet::ICMPv6::solicited_node_multicast(source);
    assert(solicited[0] == 0xFFU && solicited[1] == 0x02U && solicited[11] == 0x01U && solicited[12] == 0xFFU &&
           solicited[13] == source[13] && solicited[14] == source[14] && solicited[15] == source[15]);
    const auto multicast_mac = skan::packet::ICMPv6::ethernet_multicast(solicited);
    const std::array<std::uint8_t, 6U> expected_multicast_mac{0x33U, 0x33U, 0xFFU, source[13], source[14], source[15]};
    assert(multicast_mac == expected_multicast_mac);
    assert(!skan::packet::ICMPv6::make_neighbor_solicitation({}, mac).has_value());
    assert(!skan::packet::ICMPv6::make_neighbor_advertisement(
        std::array<std::uint8_t, 16U>{0xFFU}, mac).has_value());

    echo.set_code(1U);
    assert(!echo.validate());
    skan::packet::ICMPv6 unreachable(skan::packet::Icmpv6Type::DestinationUnreachable);
    unreachable.set_code(1U);
    assert(unreachable.validate());
    return 0;
}
