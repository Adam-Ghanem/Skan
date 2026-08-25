#include "net/packet_receiver.hpp"

#include <algorithm>
#include <utility>

#include "packet/checksum.hpp"

namespace skan::net {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::size_t kMaximumFrameSize = 65535U;

std::uint16_t read_u16(std::span<const std::uint8_t> input, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(input[offset]) << 8U) |
           static_cast<std::uint16_t>(input[offset + 1U]);
}

} // namespace

const char *parse_status_name(ParseStatus status) noexcept
{
    switch (status) {
    case ParseStatus::Valid:
        return "valid";
    case ParseStatus::EmptyFrame:
        return "empty-frame";
    case ParseStatus::OversizedFrame:
        return "oversized-frame";
    case ParseStatus::TruncatedEthernet:
        return "truncated-ethernet";
    case ParseStatus::MalformedEthernet:
        return "malformed-ethernet";
    case ParseStatus::UnsupportedEtherType:
        return "unsupported-ether-type";
    case ParseStatus::TruncatedIPv4:
        return "truncated-ipv4";
    case ParseStatus::MalformedIPv4:
        return "malformed-ipv4";
    case ParseStatus::TruncatedIPv6:
        return "truncated-ipv6";
    case ParseStatus::MalformedIPv6:
        return "malformed-ipv6";
    case ParseStatus::UnsupportedIPv6Extension:
        return "unsupported-ipv6-extension";
    case ParseStatus::MalformedIPv6Extension:
        return "malformed-ipv6-extension";
    case ParseStatus::IPv6ExtensionLimitExceeded:
        return "ipv6-extension-limit-exceeded";
    case ParseStatus::UnsupportedIpProtocol:
        return "unsupported-ip-protocol";
    case ParseStatus::TruncatedTCP:
        return "truncated-tcp";
    case ParseStatus::MalformedTCP:
        return "malformed-tcp";
    case ParseStatus::TruncatedUDP:
        return "truncated-udp";
    case ParseStatus::MalformedUDP:
        return "malformed-udp";
    case ParseStatus::TruncatedICMP:
        return "truncated-icmp";
    case ParseStatus::MalformedICMP:
        return "malformed-icmp";
    case ParseStatus::TruncatedICMPv6:
        return "truncated-icmpv6";
    case ParseStatus::MalformedICMPv6:
        return "malformed-icmpv6";
    }
    return "unknown";
}

PacketObservation PacketReceiver::parse(
    std::span<const std::uint8_t> frame,
    std::chrono::steady_clock::time_point received_at,
    std::size_t max_frame_size)
{
    PacketObservation observation;
    observation.received_at = received_at;
    const std::size_t effective_max_frame_size = std::min(max_frame_size, kMaximumFrameSize);
    if (effective_max_frame_size == 0U || frame.size() > effective_max_frame_size) {
        observation.status = ParseStatus::OversizedFrame;
        return observation;
    }
    if (frame.empty()) {
        observation.status = ParseStatus::EmptyFrame;
        return observation;
    }
    observation.raw_frame.assign(frame.begin(), frame.end());
    if (frame.size() < packet::Ethernet::kHeaderSize) {
        observation.status = ParseStatus::TruncatedEthernet;
        return observation;
    }
    observation.ethernet = packet::Ethernet::parse(frame.first(packet::Ethernet::kHeaderSize));
    if (!observation.ethernet.has_value()) {
        observation.status = ParseStatus::MalformedEthernet;
        return observation;
    }
    if (observation.ethernet->ether_type() == kEtherTypeIpv6) {
        const std::span<const std::uint8_t> ip_input = frame.subspan(packet::Ethernet::kHeaderSize);
        if (ip_input.size() < packet::IPv6::kHeaderSize) {
            observation.status = ParseStatus::TruncatedIPv6;
            return observation;
        }
        observation.ipv6 = packet::IPv6::parse(ip_input);
        if (!observation.ipv6.has_value()) {
            observation.status = ParseStatus::MalformedIPv6;
            return observation;
        }
        const std::size_t ipv6_payload_size = static_cast<std::size_t>(observation.ipv6->payload_length());
        const std::span<const std::uint8_t> ip_packet = ip_input.first(packet::IPv6::kHeaderSize + ipv6_payload_size);
        const std::span<const std::uint8_t> ipv6_payload = ip_packet.subspan(packet::IPv6::kHeaderSize);
        observation.ipv6_extensions = packet::parse_ipv6_extensions(
            ipv6_payload, observation.ipv6->next_header(), 8U, 2048U);
        switch (observation.ipv6_extensions.status) {
        case packet::IPv6ExtensionParseStatus::Malformed:
            observation.status = ParseStatus::MalformedIPv6Extension;
            return observation;
        case packet::IPv6ExtensionParseStatus::LimitExceeded:
            observation.status = ParseStatus::IPv6ExtensionLimitExceeded;
            return observation;
        case packet::IPv6ExtensionParseStatus::Unsupported:
            observation.status = ParseStatus::UnsupportedIPv6Extension;
            return observation;
        case packet::IPv6ExtensionParseStatus::NoNextHeader:
            observation.status = ParseStatus::UnsupportedIpProtocol;
            return observation;
        case packet::IPv6ExtensionParseStatus::Complete:
            break;
        }
        const std::span<const std::uint8_t> transport = ipv6_payload.subspan(observation.ipv6_extensions.consumed_bytes);
        switch (observation.ipv6_extensions.terminal_next_header) {
        case 6U:
            if (transport.size() < packet::TCP::kMinimumHeaderSize) {
                observation.status = ParseStatus::TruncatedTCP;
                return observation;
            }
            observation.tcp = packet::TCP::parse(transport);
            if (!observation.tcp.has_value()) {
                observation.status = ParseStatus::MalformedTCP;
                return observation;
            }
            break;
        case 17U: {
            if (transport.size() < packet::UDP::kHeaderSize) {
                observation.status = ParseStatus::TruncatedUDP;
                return observation;
            }
            const std::size_t udp_length = read_u16(transport, 4U);
            if (udp_length < packet::UDP::kHeaderSize) {
                observation.status = ParseStatus::MalformedUDP;
                return observation;
            }
            if (udp_length > transport.size()) {
                observation.status = ParseStatus::TruncatedUDP;
                return observation;
            }
            observation.udp = packet::UDP::parse(transport.first(udp_length));
            if (!observation.udp.has_value()) {
                observation.status = ParseStatus::MalformedUDP;
                return observation;
            }
            break;
        }
        case 58U:
            if (transport.size() < packet::ICMPv6::kHeaderSize) {
                observation.status = ParseStatus::TruncatedICMPv6;
                return observation;
            }
            observation.icmpv6 = packet::ICMPv6::parse(transport);
            if (!observation.icmpv6.has_value() || packet::checksum::ipv6_pseudo_header(
                    observation.ipv6->source_address(), observation.ipv6->destination_address(), 58U, transport) != 0U) {
                observation.status = ParseStatus::MalformedICMPv6;
                return observation;
            }
            break;
        default:
            observation.status = ParseStatus::UnsupportedIpProtocol;
            return observation;
        }
        observation.status = ParseStatus::Valid;
        return observation;
    }
    if (observation.ethernet->ether_type() != kEtherTypeIpv4) {
        observation.status = ParseStatus::UnsupportedEtherType;
        return observation;
    }

    const std::span<const std::uint8_t> ip_input = frame.subspan(packet::Ethernet::kHeaderSize);
    if (ip_input.size() < packet::IPv4::kMinimumHeaderSize) {
        observation.status = ParseStatus::TruncatedIPv4;
        return observation;
    }
    const std::uint8_t version = static_cast<std::uint8_t>(ip_input[0] >> 4U);
    const std::uint8_t ihl = static_cast<std::uint8_t>(ip_input[0] & 0x0FU);
    const std::size_t ip_header_size = static_cast<std::size_t>(ihl) * 4U;
    if (version != 4U || ihl != 5U) {
        observation.status = ParseStatus::MalformedIPv4;
        return observation;
    }
    if (ip_input.size() < ip_header_size) {
        observation.status = ParseStatus::TruncatedIPv4;
        return observation;
    }
    const std::uint16_t total_length = read_u16(ip_input, 2U);
    if (total_length < ip_header_size) {
        observation.status = ParseStatus::MalformedIPv4;
        return observation;
    }
    if (static_cast<std::size_t>(total_length) > ip_input.size()) {
        observation.status = ParseStatus::TruncatedIPv4;
        return observation;
    }
    const std::span<const std::uint8_t> ip_packet = ip_input.first(total_length);
    observation.ipv4 = packet::IPv4::parse(ip_packet);
    if (!observation.ipv4.has_value()) {
        observation.status = ParseStatus::MalformedIPv4;
        return observation;
    }

    const std::span<const std::uint8_t> transport = ip_packet.subspan(ip_header_size);
    switch (observation.ipv4->protocol()) {
    case 6U:
        if (transport.size() < packet::TCP::kMinimumHeaderSize) {
            observation.status = ParseStatus::TruncatedTCP;
            return observation;
        }
        observation.tcp = packet::TCP::parse(transport);
        if (!observation.tcp.has_value()) {
            observation.status = ParseStatus::MalformedTCP;
            return observation;
        }
        break;
    case 17U: {
        if (transport.size() < packet::UDP::kHeaderSize) {
            observation.status = ParseStatus::TruncatedUDP;
            return observation;
        }
        const std::size_t udp_length = read_u16(transport, 4U);
        if (udp_length < packet::UDP::kHeaderSize) {
            observation.status = ParseStatus::MalformedUDP;
            return observation;
        }
        if (udp_length > transport.size()) {
            observation.status = ParseStatus::TruncatedUDP;
            return observation;
        }
        observation.udp = packet::UDP::parse(transport.first(udp_length));
        if (!observation.udp.has_value()) {
            observation.status = ParseStatus::MalformedUDP;
            return observation;
        }
        break;
    }
    case 1U:
        if (transport.size() < packet::ICMP::kHeaderSize) {
            observation.status = ParseStatus::TruncatedICMP;
            return observation;
        }
        observation.icmp = packet::ICMP::parse(transport);
        if (!observation.icmp.has_value()) {
            observation.status = ParseStatus::MalformedICMP;
            return observation;
        }
        break;
    default:
        observation.status = ParseStatus::UnsupportedIpProtocol;
        return observation;
    }
    observation.status = ParseStatus::Valid;
    return observation;
}

PacketReceiver::PacketReceiver(PacketCapture &capture, std::size_t max_frame_size)
    : capture_(capture),
      max_frame_size_(std::min(max_frame_size, kMaximumFrameSize)),
      receive_buffer_(std::min(max_frame_size, kMaximumFrameSize))
{
}

CaptureResult PacketReceiver::open(const CaptureConfig &config)
{
    if (config.max_frame_size == 0U || config.max_frame_size > max_frame_size_) {
        return capture_failure(CaptureStatus::InvalidConfiguration, 0, "receiver frame limit is invalid");
    }
    return capture_.open(config);
}

void PacketReceiver::close() noexcept
{
    if (attached_engine_ != nullptr && event_.has_value()) {
        const core::StatusCode status = attached_engine_->remove(*event_);
        if (status != core::StatusCode::Ok && status != core::StatusCode::NotFound && event_->registered()) {
            return;
        }
        event_.reset();
        attached_engine_ = nullptr;
    }
    capture_.close();
}

bool PacketReceiver::is_open() const noexcept
{
    return capture_.is_open();
}

ReceiverResult PacketReceiver::receive(std::chrono::steady_clock::time_point received_at)
{
    ReceiverResult result;
    result.capture = capture_.receive(std::span<std::uint8_t>{receive_buffer_});
    if (!result.capture.success()) {
        return result;
    }
    PacketObservation observation = parse(
        std::span<const std::uint8_t>{receive_buffer_}.first(result.capture.bytes_received),
        received_at,
        max_frame_size_);
    last_observation_ = observation;
    result.observation = std::move(observation);
    return result;
}

core::StatusCode PacketReceiver::attach(io::IOEngine &io_engine, io::EventCallback callback)
{
    if (!is_open() || capture_.file_descriptor() < 0 || !callback || event_.has_value()) {
        return core::StatusCode::InvalidArgument;
    }
    event_.emplace(
        capture_.file_descriptor(),
        io::EventMask::Read | io::EventMask::Error | io::EventMask::Hangup,
        std::move(callback),
        this);
    const core::StatusCode status = io_engine.add(*event_);
    if (status != core::StatusCode::Ok) {
        event_.reset();
        return status;
    }
    attached_engine_ = &io_engine;
    return core::StatusCode::Ok;
}

core::StatusCode PacketReceiver::detach(io::IOEngine &io_engine) noexcept
{
    if (!event_.has_value()) {
        return core::StatusCode::Ok;
    }
    if (attached_engine_ != &io_engine) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode status = io_engine.remove(*event_);
    if (status != core::StatusCode::Ok && status != core::StatusCode::NotFound && event_->registered()) {
        return status;
    }
    event_.reset();
    attached_engine_ = nullptr;
    return core::StatusCode::Ok;
}

int PacketReceiver::file_descriptor() const noexcept
{
    return capture_.file_descriptor();
}

const PacketObservation &PacketReceiver::last_observation() const noexcept
{
    static const PacketObservation empty_observation{};
    return last_observation_.has_value() ? *last_observation_ : empty_observation;
}

} // namespace skan::net
