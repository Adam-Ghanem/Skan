#ifndef SKAN_NET_PACKET_RECEIVER_HPP
#define SKAN_NET_PACKET_RECEIVER_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

namespace skan::net {

enum class ParseStatus {
    Valid,
    EmptyFrame,
    OversizedFrame,
    TruncatedEthernet,
    MalformedEthernet,
    UnsupportedEtherType,
    TruncatedIPv4,
    MalformedIPv4,
    UnsupportedIpProtocol,
    TruncatedTCP,
    MalformedTCP,
    TruncatedUDP,
    MalformedUDP,
    TruncatedICMP,
    MalformedICMP
};

const char *parse_status_name(ParseStatus status) noexcept;

struct PacketObservation final {
    std::chrono::steady_clock::time_point received_at{};
    std::vector<std::uint8_t> raw_frame;
    std::optional<packet::Ethernet> ethernet;
    std::optional<packet::IPv4> ipv4;
    std::optional<packet::TCP> tcp;
    std::optional<packet::UDP> udp;
    std::optional<packet::ICMP> icmp;
    ParseStatus status{ParseStatus::EmptyFrame};

    bool valid() const noexcept { return status == ParseStatus::Valid; }
};

struct ReceiverResult final {
    CaptureResult capture;
    std::optional<PacketObservation> observation;

    bool success() const noexcept
    {
        return capture.status == CaptureStatus::Success && observation.has_value() && observation->valid();
    }
};

class PacketReceiver final {
public:
    explicit PacketReceiver(PacketCapture &capture, std::size_t max_frame_size = 65535U);
    ~PacketReceiver() noexcept { close(); }

    CaptureResult open(const CaptureConfig &config);
    void close() noexcept;
    bool is_open() const noexcept;

    ReceiverResult receive(
        std::chrono::steady_clock::time_point received_at = std::chrono::steady_clock::now());

    static PacketObservation parse(
        std::span<const std::uint8_t> frame,
        std::chrono::steady_clock::time_point received_at = std::chrono::steady_clock::now(),
        std::size_t max_frame_size = 65535U);

    /** Register the capture descriptor with the existing single reactor. */
    core::StatusCode attach(io::IOEngine &io_engine, io::EventCallback callback);
    core::StatusCode detach(io::IOEngine &io_engine) noexcept;

    int file_descriptor() const noexcept;
    const PacketObservation &last_observation() const noexcept;

private:
    PacketCapture &capture_;
    std::size_t max_frame_size_;
    std::vector<std::uint8_t> receive_buffer_;
    std::optional<PacketObservation> last_observation_;
    std::optional<io::Event> event_;
    io::IOEngine *attached_engine_{nullptr};
};

} // namespace skan::net

#endif // SKAN_NET_PACKET_RECEIVER_HPP
