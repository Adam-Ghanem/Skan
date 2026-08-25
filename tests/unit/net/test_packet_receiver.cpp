#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>
#include <unistd.h>

#include "net/packet_receiver.hpp"
#include "net/capture.hpp"
#include "packet/checksum.hpp"
#include "packet/packet.hpp"

#include "net_test_fixture.hpp"

namespace {

class PipeCapture final : public skan::net::PacketCapture {
public:
    PipeCapture()
    {
        assert(::pipe(descriptors_) == 0);
    }

    ~PipeCapture() override { close(); }

    skan::net::CaptureResult open(const skan::net::CaptureConfig &config) override
    {
        if (config.max_frame_size == 0U || descriptors_[0] < 0) {
            return skan::net::capture_failure(skan::net::CaptureStatus::InvalidConfiguration, 0, "invalid fixture");
        }
        open_ = true;
        return skan::net::capture_success(0U);
    }

    skan::net::CaptureResult receive(std::span<std::uint8_t> buffer) override
    {
        if (!open_) {
            return skan::net::capture_failure(skan::net::CaptureStatus::NotOpen, 0, "fixture is closed");
        }
        const ssize_t count = ::read(descriptors_[0], buffer.data(), buffer.size());
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return skan::net::capture_failure(skan::net::CaptureStatus::WouldBlock, errno, "fixture would block");
        }
        if (count <= 0) {
            return skan::net::capture_failure(skan::net::CaptureStatus::ReceiveFailed, errno, "fixture read failed");
        }
        return skan::net::capture_success(static_cast<std::size_t>(count));
    }

    void close() noexcept override
    {
        open_ = false;
        for (int &descriptor : descriptors_) {
            if (descriptor >= 0) {
                (void)::close(descriptor);
                descriptor = -1;
            }
        }
    }

    bool is_open() const noexcept override { return open_; }
    int file_descriptor() const noexcept override { return descriptors_[0]; }

    void enqueue(std::span<const std::uint8_t> frame)
    {
        assert(::write(descriptors_[1], frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()));
    }

private:
    int descriptors_[2]{-1, -1};
    bool open_{false};
};

std::vector<std::uint8_t> test_ipv6_frame()
{
    const std::array<std::uint8_t, 16U> source{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
    const std::array<std::uint8_t, 16U> destination{
        0x20U, 0x01U, 0x0DU, 0xB8U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
    skan::packet::Ethernet ethernet(
        {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U},
        {0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU}, 0x86DDU);
    skan::packet::IPv6 ipv6;
    ipv6.set_next_header(58U);
    ipv6.set_source_address(source);
    ipv6.set_destination_address(destination);
    skan::packet::ICMPv6 icmpv6(skan::packet::Icmpv6Type::EchoReply);
    icmpv6.set_identifier(7U);
    icmpv6.set_sequence(8U);
    icmpv6.set_payload({0x6FU, 0x6BU});
    skan::packet::Packet packet;
    packet.set_ethernet(ethernet);
    packet.set_ipv6(ipv6);
    packet.set_icmpv6(icmpv6);
    assert(packet.validate());
    return packet.serialize();
}

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

    auto padded_udp_frame = udp_frame;
    padded_udp_frame.insert(padded_udp_frame.end(), {0xAAU, 0xBBU, 0xCCU, 0xDDU});
    const auto original_ip_total_length = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(padded_udp_frame[16U]) << 8U) | padded_udp_frame[17U]);
    set_ipv4_total_length(
        padded_udp_frame,
        static_cast<std::uint16_t>(original_ip_total_length + 4U));
    const skan::net::PacketObservation padded_udp = skan::net::PacketReceiver::parse(padded_udp_frame, timestamp);
    assert(padded_udp.status == skan::net::ParseStatus::Valid);
    assert(padded_udp.udp.has_value());
    assert(padded_udp.udp->payload() == udp.udp->payload());

    const auto icmp_frame = skan::test::test_icmp_frame();
    const skan::net::PacketObservation icmp = skan::net::PacketReceiver::parse(icmp_frame, timestamp);
    assert(icmp.status == skan::net::ParseStatus::Valid);
    assert(icmp.icmp.has_value());

    assert(skan::net::PacketReceiver::parse({}).status == skan::net::ParseStatus::EmptyFrame);
    const std::vector<std::uint8_t> oversized_frame(65536U, 0U);
    assert(skan::net::PacketReceiver::parse(oversized_frame, timestamp, 1000000U).status ==
           skan::net::ParseStatus::OversizedFrame);
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

    const auto ipv6_frame = test_ipv6_frame();
    const skan::net::PacketObservation ipv6 = skan::net::PacketReceiver::parse(ipv6_frame, timestamp);
    assert(ipv6.status == skan::net::ParseStatus::Valid);
    assert(ipv6.ipv6.has_value());
    assert(ipv6.icmpv6.has_value());
    assert(ipv6.icmpv6->sequence() == 8U);

    auto malformed_ipv6 = ipv6_frame;
    malformed_ipv6[14U] = 0x45U;
    assert(skan::net::PacketReceiver::parse(malformed_ipv6).status == skan::net::ParseStatus::MalformedIPv6);

    auto unsupported = tcp_frame;
    unsupported[12U] = 0x12U;
    unsupported[13U] = 0x34U;
    assert(skan::net::PacketReceiver::parse(unsupported).status == skan::net::ParseStatus::UnsupportedEtherType);

    skan::net::RecordingCapture capture;
    capture.enqueue(tcp_frame);
    skan::net::PacketReceiver receiver(capture);
    assert(receiver.open(skan::net::CaptureConfig{"offline", 65535U, true}).success());
    const skan::net::ReceiverResult received = receiver.receive(timestamp);
    assert(received.success());
    assert(received.observation->received_at == timestamp);
    receiver.close();
    assert(!receiver.is_open());

    PipeCapture pipe_capture;
    skan::net::PacketReceiver attached_receiver(pipe_capture);
    skan::io::IOEngine engine;
    assert(attached_receiver.open(skan::net::CaptureConfig{"pipe", 65535U, true}).success());
    bool callback_called = false;
    assert(attached_receiver.attach(
               engine,
               [&attached_receiver, &callback_called](skan::io::Event &) {
                   const skan::net::ReceiverResult result = attached_receiver.receive();
                   assert(result.success());
                   callback_called = true;
               }) == skan::core::StatusCode::Ok);
    pipe_capture.enqueue(tcp_frame);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(callback_called);
    assert(attached_receiver.detach(engine) == skan::core::StatusCode::Ok);
    assert(attached_receiver.detach(engine) == skan::core::StatusCode::Ok);

    PipeCapture close_capture;
    skan::net::PacketReceiver close_receiver(close_capture);
    skan::io::IOEngine close_engine;
    assert(close_receiver.open(skan::net::CaptureConfig{"pipe", 65535U, true}).success());
    assert(close_receiver.attach(close_engine, [](skan::io::Event &) {}) == skan::core::StatusCode::Ok);
    close_receiver.close();
    assert(!close_receiver.is_open());
    assert(close_engine.run_once(0) == skan::core::StatusCode::Ok);

    PipeCapture shutdown_capture;
    skan::net::PacketReceiver shutdown_receiver(shutdown_capture);
    skan::io::IOEngine shutdown_engine;
    assert(shutdown_receiver.open(skan::net::CaptureConfig{"pipe", 65535U, true}).success());
    assert(shutdown_receiver.attach(shutdown_engine, [](skan::io::Event &) {}) == skan::core::StatusCode::Ok);
    assert(shutdown_engine.shutdown() == skan::core::StatusCode::Ok);
    shutdown_receiver.close();
    assert(!shutdown_receiver.is_open());
    return 0;
}
