#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/ipv6.hpp"
#include "packet/ipv6_extensions.hpp"

int main()
{
    const std::array<std::uint8_t, 16U> source{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
    const std::array<std::uint8_t, 16U> destination{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};

    skan::packet::IPv6 header;
    header.set_traffic_class(0xABU);
    header.set_flow_label(0x54321U);
    header.set_payload_length(0x1234U);
    header.set_next_header(17U);
    header.set_hop_limit(64U);
    header.set_source_address(source);
    header.set_destination_address(destination);
    assert(header.validate());

    std::vector<std::uint8_t> bytes(40U, 0U);
    assert(header.serialize(std::span<std::uint8_t>{bytes}) == skan::core::StatusCode::Ok);
    assert(bytes[0] == 0x6AU && bytes[1] == 0xB5U && bytes[2] == 0x43U && bytes[3] == 0x21U);
    assert(bytes[4] == 0x12U && bytes[5] == 0x34U && bytes[6] == 17U && bytes[7] == 64U);
    assert(std::equal(source.begin(), source.end(), bytes.begin() + 8));
    assert(std::equal(destination.begin(), destination.end(), bytes.begin() + 24));

    std::vector<std::uint8_t> with_payload = bytes;
    with_payload.resize(40U + 0x1234U, 0U);
    const auto parsed = skan::packet::IPv6::parse(std::span<const std::uint8_t>{with_payload});
    assert(parsed.has_value());
    assert(parsed->traffic_class() == 0xABU);
    assert(parsed->flow_label() == 0x54321U);
    assert(parsed->payload_length() == 0x1234U);
    assert(parsed->next_header() == 17U);
    assert(parsed->source_address() == source && parsed->destination_address() == destination);

    with_payload.resize(40U + 0x1233U);
    assert(!skan::packet::IPv6::parse(std::span<const std::uint8_t>{with_payload}).has_value());
    assert(!skan::packet::IPv6::parse(std::span<const std::uint8_t>{bytes.data(), 39U}).has_value());

    header.set_version(4U);
    assert(!header.validate());
    header.set_version(6U);
    header.set_flow_label(0xFFFFFFFFU);
    assert(header.flow_label() == 0xFFFFFU);

    std::vector<std::uint8_t> extensions(16U + 20U, 0U);
    extensions[0] = 60U;
    extensions[1] = 0U;
    extensions[8] = 6U;
    extensions[9] = 0U;
    const auto extension_result = skan::packet::parse_ipv6_extensions(
        std::span<const std::uint8_t>{extensions}, 0U, 4U, 64U);
    assert(extension_result.status == skan::packet::IPv6ExtensionParseStatus::Complete);
    assert(extension_result.headers.size() == 2U);
    assert(extension_result.consumed_bytes == 16U);
    assert(extension_result.terminal_next_header == 6U);

    const std::vector<std::uint8_t> malformed_extension{6U, 1U};
    assert(skan::packet::parse_ipv6_extensions(
               std::span<const std::uint8_t>{malformed_extension}, 0U).status ==
           skan::packet::IPv6ExtensionParseStatus::Malformed);
    const std::vector<std::uint8_t> unsupported_extension{};
    assert(skan::packet::parse_ipv6_extensions(
               std::span<const std::uint8_t>{unsupported_extension}, 51U).status ==
           skan::packet::IPv6ExtensionParseStatus::Unsupported);
    assert(skan::packet::parse_ipv6_extensions(
               std::span<const std::uint8_t>{extensions}, 0U, 1U, 64U).status ==
           skan::packet::IPv6ExtensionParseStatus::LimitExceeded);
    return 0;
}
