#include <cassert>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

#include "net/packet_receiver.hpp"
#include "net/capture.hpp"
#include "packet/checksum.hpp"

#include "net_test_fixture.hpp"

namespace {

void set_ipv4_total_length(std::vector<std::uint8_t> &frame, std::uint16_t total_length)
{
    frame[16] = static_cast<std::uint8_t>(total_length >> 8U);
    frame[17] = static_cast<std::uint8_t>(total_length & 0xFFU);
    frame[24] = 0U;
    frame[25] = 0U;
    const std::uint16_t checksum = skan::packet::checksum::internet(
        std::span<const std::uint8_t>{frame}.subspan(14U, 20U));
    frame[24] = static_cast<std::uint8_t>(checksum >> 8U);
    frame[25] = static_cast<std::uint8_t>(checksum & 0xFFU);
}

} // namespace

int main()
{
    const auto timestamp = std::chrono::steady_clock::time_point{std::chrono::seconds{42}};

    const auto tcp_frame = skan::test::test_tcp_frame();
    const skan::net::PacketObservation tcp = skan::net::PacketReceiver::parse(tcp_frame, timestamp);
    assert(tcp.status == skan::net::ParseStatus::Valid);
    assert(tcp.tcp.has_value());
    assert(tcp.tcp->source_port() == 12345U);
    assert(tcp.received_at == timestamp);

    const auto udp_frame = skan::test::test_udp_frame();
    const skan::net::PacketObservation udp = skan::net::PacketReceiver::parse(udp_frame, timestamp);
    assert(udp.status == skan::net::ParseStatus::Valid);
    assert(udp.udp.has_value());
    assert(udp.udp->destination_port() == 53U);

    const auto icmp_frame = skan::test::test_icmp_frame();
    const skan::net::PacketObservation icmp = skan::net::PacketReceiver::parse(icmp_frame, timestamp);
    assert(icmp.status == skan::net::ParseStatus::Valid);
    assert(icmp.icmp.has_value());

    assert(skan::net::PacketReceiver::parse({}).status == skan::net::ParseStatus::EmptyFrame);
    assert(skan::net::PacketReceiver::parse(std::span<const std::uint8_t>{tcp_frame}.first(5U)).status ==
           skan::net::ParseStatus::TruncatedEthernet);
    assert(skan::net::PacketReceiver::parse(std::span<const std::uint8_t>{tcp_frame}.first(14U + 10U)).status ==
           skan::net::ParseStatus::TruncatedIPv4);

    auto malformed_ipv4 = tcp_frame;
    malformed_ipv4[14] = 0x65U;
    assert(skan::net::PacketReceiver::parse(malformed_ipv4).status == skan::net::ParseStatus::MalformedIPv4);

    auto truncated_tcp = tcp_frame;
    truncated_tcp.resize(14U + 20U + 10U);
    set_ipv4_total_length(truncated_tcp, 30U);
    assert(skan::net::PacketReceiver::parse(truncated_tcp).status == skan::net::ParseStatus::TruncatedTCP);

    auto malformed_tcp = tcp_frame;
    malformed_tcp[14U + 20U + 12U] = 0x40U;
    assert(skan::net::PacketReceiver::parse(malformed_tcp).status == skan::net::ParseStatus::MalformedTCP);

    auto malformed_udp = udp_frame;
    malformed_udp[14U + 20U + 4U] = 0U;
    malformed_udp[14U + 20U + 5U] = 1U;
    assert(skan::net::PacketReceiver::parse(malformed_udp).status == skan::net::ParseStatus::MalformedUDP);

    auto malformed_icmp = icmp_frame;
    malformed_icmp[14U + 20U + 2U] ^= 0x01U;
    assert(skan::net::PacketReceiver::parse(malformed_icmp).status == skan::net::ParseStatus::MalformedICMP);

    auto unrelated = tcp_frame;
    unrelated[12U] = 0x86U;
    unrelated[13U] = 0xDDU;
    const skan::net::PacketObservation unsupported = skan::net::PacketReceiver::parse(unrelated);
    assert(unsupported.status == skan::net::ParseStatus::UnsupportedEtherType);
    assert(unsupported.ethernet.has_value());

    skan::net::RecordingCapture capture;
    capture.enqueue(tcp_frame);
    skan::net::PacketReceiver receiver(capture);
    assert(receiver.open(skan::net::CaptureConfig{"offline", 65535U, true}).success());
    const skan::net::ReceiverResult received = receiver.receive(timestamp);
    assert(received.success());
    assert(received.observation->received_at == timestamp);
    receiver.close();
    assert(!receiver.is_open());
    return 0;
}
