#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/packet.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

namespace {

skan::packet::IPv4 base_ipv4(std::uint8_t protocol)
{
    skan::packet::IPv4 ipv4;
    ipv4.set_protocol(protocol);
    ipv4.set_source_address(0xC0000201U);
    ipv4.set_destination_address(0xC6336402U);
    ipv4.set_ttl(64U);
    return ipv4;
}

} // namespace

int main()
{
    const skan::packet::Ethernet ethernet(
        {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U},
        {0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU},
        0x0800U);

    skan::packet::TCP tcp;
    tcp.set_source_port(12345U);
    tcp.set_destination_port(80U);
    tcp.set_sequence_number(0x11223344U);
    tcp.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Syn));
    tcp.set_window(0xFAF0U);

    skan::packet::Packet tcp_packet;
    tcp_packet.set_ethernet(ethernet);
    tcp_packet.set_ipv4(base_ipv4(6U));
    tcp_packet.set_tcp(tcp);
    assert(tcp_packet.validate());
    assert(tcp_packet.serialized_size() == 14U + 20U + 20U);
    const std::vector<std::uint8_t> tcp_bytes = tcp_packet.serialize();
    assert(tcp_bytes.size() == tcp_packet.serialized_size());
    assert(tcp_bytes[12] == 0x08U && tcp_bytes[13] == 0x00U);
    assert(tcp_bytes[14] == 0x45U);
    assert(tcp_bytes[23] == 6U);
    assert(tcp_bytes[34] == 0x30U && tcp_bytes[35] == 0x39U);
    assert(tcp_bytes[36] == 0x00U && tcp_bytes[37] == 0x50U);
    assert((tcp_bytes[14 + 20U + 13U] & 0x02U) != 0U);
    assert(skan::packet::checksum::internet(std::span<const std::uint8_t>{tcp_bytes.data() + 14U, 20U}) == 0U);
    assert(skan::packet::checksum::ipv4_pseudo_header(
        0xC0000201U, 0xC6336402U, 6U,
        std::span<const std::uint8_t>{tcp_bytes.data() + 14U + 20U, 20U}) == 0U);
    assert(tcp_bytes[16] == 0x00U && tcp_bytes[17] == 0x28U);

    skan::packet::UDP udp;
    udp.set_source_port(5353U);
    udp.set_destination_port(53U);
    udp.set_payload({0x01U, 0x02U, 0x03U});
    skan::packet::Packet udp_packet;
    udp_packet.set_ipv4(base_ipv4(17U));
    udp_packet.set_udp(udp);
    assert(udp_packet.validate());
    const std::vector<std::uint8_t> udp_bytes = udp_packet.serialize();
    assert(udp_bytes.size() == 20U + 11U);
    assert(udp_bytes[9] == 17U);
    assert(udp_bytes[20] == 0x14U && udp_bytes[21] == 0xE9U);
    assert(udp_bytes[24] == 0x00U && udp_bytes[25] == 0x0BU);
    assert(skan::packet::checksum::ipv4_pseudo_header(
        0xC0000201U, 0xC6336402U, 17U,
        std::span<const std::uint8_t>{udp_bytes.data() + 20U, 11U}) == 0U);

    skan::packet::ICMP icmp(skan::packet::IcmpType::EchoRequest);
    icmp.set_identifier(7U);
    icmp.set_sequence(8U);
    icmp.set_payload({0x70U, 0x69U, 0x6EU, 0x67U});
    skan::packet::Packet icmp_packet;
    icmp_packet.set_ipv4(base_ipv4(1U));
    icmp_packet.set_icmp(icmp);
    assert(icmp_packet.validate());
    const std::vector<std::uint8_t> icmp_bytes = icmp_packet.serialize();
    assert(icmp_bytes.size() == 32U);
    assert(icmp_bytes[9] == 1U);
    assert(icmp_bytes[20] == 8U);
    assert(icmp_bytes[24] == 0U && icmp_bytes[25] == 7U);
    assert(skan::packet::checksum::internet(
        std::span<const std::uint8_t>{icmp_bytes.data() + 20U, 12U}) == 0U);

    skan::packet::Packet invalid_packet;
    invalid_packet.set_tcp(tcp);
    assert(!invalid_packet.validate());
    assert(invalid_packet.serialize().empty());
    return 0;
}
