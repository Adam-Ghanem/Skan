#ifndef SKAN_TESTS_UNIT_NET_NET_TEST_FIXTURE_HPP
#define SKAN_TESTS_UNIT_NET_NET_TEST_FIXTURE_HPP

#include <cstdint>
#include <vector>

#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/packet.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

namespace skan::test {

inline packet::IPv4 test_ipv4(std::uint8_t protocol)
{
    packet::IPv4 ipv4;
    ipv4.set_protocol(protocol);
    ipv4.set_source_address(0xC0000201U);
    ipv4.set_destination_address(0xC6336402U);
    ipv4.set_ttl(64U);
    return ipv4;
}

inline packet::Ethernet test_ethernet(std::uint16_t ether_type = 0x0800U)
{
    return packet::Ethernet(
        {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U},
        {0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU},
        ether_type);
}

inline std::vector<std::uint8_t> test_tcp_frame(
    std::uint16_t source_port = 12345U,
    std::uint16_t destination_port = 80U)
{
    packet::TCP tcp;
    tcp.set_source_port(source_port);
    tcp.set_destination_port(destination_port);
    tcp.set_sequence_number(0x11223344U);
    tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Syn));
    tcp.set_window(0xFAF0U);
    packet::Packet composed;
    composed.set_ethernet(test_ethernet());
    composed.set_ipv4(test_ipv4(6U));
    composed.set_tcp(tcp);
    return composed.serialize();
}

inline std::vector<std::uint8_t> test_udp_frame(
    std::uint16_t source_port = 5353U,
    std::uint16_t destination_port = 53U)
{
    packet::UDP udp;
    udp.set_source_port(source_port);
    udp.set_destination_port(destination_port);
    udp.set_payload({0x01U, 0x02U, 0x03U});
    packet::Packet composed;
    composed.set_ethernet(test_ethernet());
    composed.set_ipv4(test_ipv4(17U));
    composed.set_udp(udp);
    return composed.serialize();
}

inline packet::IPv6 test_ipv6(std::uint8_t next_header)
{
    packet::IPv6 ipv6;
    ipv6.set_next_header(next_header);
    ipv6.set_source_address({0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x01U,
                             0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U});
    ipv6.set_destination_address({0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x02U,
                                  0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U});
    return ipv6;
}

inline std::vector<std::uint8_t> test_ipv6_tcp_frame()
{
    packet::TCP tcp;
    tcp.set_source_port(12345U);
    tcp.set_destination_port(80U);
    tcp.set_sequence_number(0x11223344U);
    tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Syn));
    tcp.set_window(0xFAF0U);
    packet::Packet composed;
    composed.set_ethernet(test_ethernet(0x86DDU));
    composed.set_ipv6(test_ipv6(6U));
    composed.set_tcp(tcp);
    return composed.serialize();
}

inline std::vector<std::uint8_t> test_ipv6_udp_frame()
{
    packet::UDP udp;
    udp.set_source_port(5353U);
    udp.set_destination_port(53U);
    udp.set_payload({0x01U, 0x02U, 0x03U});
    packet::Packet composed;
    composed.set_ethernet(test_ethernet(0x86DDU));
    composed.set_ipv6(test_ipv6(17U));
    composed.set_udp(udp);
    return composed.serialize();
}

inline std::vector<std::uint8_t> test_icmp_frame()
{
    packet::ICMP icmp(packet::IcmpType::EchoRequest);
    icmp.set_identifier(7U);
    icmp.set_sequence(8U);
    icmp.set_payload({0x70U, 0x69U, 0x6EU, 0x67U});
    packet::Packet composed;
    composed.set_ethernet(test_ethernet());
    composed.set_ipv4(test_ipv4(1U));
    composed.set_icmp(icmp);
    return composed.serialize();
}

} // namespace skan::test

#endif // SKAN_TESTS_UNIT_NET_NET_TEST_FIXTURE_HPP
