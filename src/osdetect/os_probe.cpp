#include "osdetect/os_probe.hpp"

#include <algorithm>
#include <new>
#include <span>
#include <utility>

#include "discovery/discovery_types.hpp"
#include "packet/checksum.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/packet.hpp"
#include "packet/udp.hpp"

namespace skan::osdetect {
namespace {

std::uint16_t source_port_for(OSProbeId id) noexcept
{
    return static_cast<std::uint16_t>(40000U + (id % 20000U));
}

std::uint32_t sequence_for(OSProbeId id) noexcept
{
    return 0x51000000U ^ static_cast<std::uint32_t>(id);
}

core::StatusCode serialize_ipv4_tcp(
    std::uint32_t source_address,
    std::uint32_t destination_address,
    std::uint8_t ttl,
    bool dont_fragment,
    packet::TCP &tcp,
    std::vector<std::uint8_t> &bytes)
{
    packet::IPv4 ip;
    ip.set_source_address(source_address);
    ip.set_destination_address(destination_address);
    ip.set_protocol(6U);
    ip.set_ttl(ttl);
    ip.set_flags_fragment_offset(dont_fragment ? 0x4000U : 0U);
    packet::Packet packet;
    packet.set_ipv4(ip);
    packet.set_tcp(tcp);
    bytes = packet.serialize();
    return bytes.empty() ? core::StatusCode::InvalidArgument : core::StatusCode::Ok;
}

class DefinedOSProbe final : public OSProbe {
public:
    explicit DefinedOSProbe(OSProbeType type) noexcept : type_(type)
    {
    }

    OSProbeType type() const noexcept override
    {
        return type_;
    }

    core::StatusCode build(
        OSProbeId id,
        const core::Host &host,
        const OSProbeConfig &config,
        OSProbeSubmission &submission) const override
    {
        const auto destination = discovery::parse_ipv4_address(host.address);
        const auto source = discovery::parse_ipv4_address(config.source_address);
        if (!destination.has_value() || !source.has_value() || config.probe_port == 0U) {
            return core::StatusCode::InvalidArgument;
        }
        submission = {};
        submission.id = id;
        submission.type = type_;
        submission.target = host.address;
        submission.destination_port = config.probe_port;
        submission.source_port = source_port_for(id);
        submission.sequence_number = sequence_for(id);
        submission.source_address = config.source_address;
        submission.generated_at = OSProbeClock::now();

        if (type_ == OSProbeType::IcmpEcho) {
            packet::ICMP icmp(packet::IcmpType::EchoRequest);
            submission.correlation_identifier = static_cast<std::uint16_t>(id & 0xFFFFU);
            submission.correlation_sequence = static_cast<std::uint16_t>((id >> 16U) & 0xFFFFU);
            icmp.set_identifier(submission.correlation_identifier);
            icmp.set_sequence(submission.correlation_sequence);
            icmp.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
            submission.bytes = icmp.serialize();
            return core::StatusCode::Ok;
        }

        if (type_ == OSProbeType::UdpFingerprint || type_ == OSProbeType::UdpPortUnreachable) {
            packet::UDP udp;
            udp.set_source_port(submission.source_port);
            udp.set_destination_port(config.udp_probe_port);
            udp.set_payload(config.udp_probe_payload);
            submission.destination_port = config.udp_probe_port;
            submission.bytes = udp.serialize();
            return submission.bytes.empty() ? core::StatusCode::InvalidArgument : core::StatusCode::Ok;
        }

        packet::TCP tcp;
        tcp.set_source_port(submission.source_port);
        tcp.set_destination_port(submission.destination_port);
        tcp.set_sequence_number(submission.sequence_number);
        tcp.set_window(64240U);
        std::uint16_t flags = static_cast<std::uint16_t>(packet::TcpFlag::Syn);
        if (type_ == OSProbeType::TcpEcn) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Syn) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Ece) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Cwr);
        } else if (type_ == OSProbeType::TcpClosedStandard) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Fin) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Psh) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Urg);
        } else if (type_ == OSProbeType::TcpClosedVariant) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Ack) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Fin);
        } else if (type_ == OSProbeType::TcpAck) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Ack);
        } else if (type_ == OSProbeType::TcpFin) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Fin);
        } else if (type_ == OSProbeType::TcpNull) {
            flags = 0U;
        } else if (type_ == OSProbeType::TcpXmas) {
            flags = static_cast<std::uint16_t>(packet::TcpFlag::Fin) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Psh) |
                    static_cast<std::uint16_t>(packet::TcpFlag::Urg);
        }
        tcp.set_flags(flags);
        if (type_ == OSProbeType::TcpSynVariant) {
            tcp.set_window(65535U);
            tcp.set_options({
                {packet::TcpOptionKind::Mss, 1460U, 0U, 0U},
                {packet::TcpOptionKind::WindowScale, 8U, 0U, 0U},
                {packet::TcpOptionKind::SackPermitted, 0U, 0U, 0U}});
        } else if (type_ == OSProbeType::TcpSynTimestamp) {
            tcp.set_options({
                {packet::TcpOptionKind::Mss, 1460U, 0U, 0U},
                {packet::TcpOptionKind::SackPermitted, 0U, 0U, 0U},
                {packet::TcpOptionKind::Timestamp, 1U, 1U, 0U},
                {packet::TcpOptionKind::WindowScale, 7U, 0U, 0U}});
        } else {
            tcp.set_options({
                {packet::TcpOptionKind::Mss, 1460U, 0U, 0U},
                {packet::TcpOptionKind::SackPermitted, 0U, 0U, 0U},
                {packet::TcpOptionKind::Timestamp, 1U, 1U, 0U},
                {packet::TcpOptionKind::WindowScale, 7U, 0U, 0U}});
        }
        const std::uint8_t ttl = type_ == OSProbeType::TcpSynVariant ? 64U : 128U;
        const bool dont_fragment = type_ != OSProbeType::TcpNull;
        return serialize_ipv4_tcp(*source, *destination, ttl, dont_fragment, tcp, submission.bytes);
    }

    OSProbeAssessment assess(
        const OSProbeResponse &response,
        const OSProbeSubmission &submission) const override
    {
        OSProbeAssessment assessment;
        if (response.kind == OSProbeResponseKind::Error) {
            assessment.status = core::StatusCode::IoError;
            assessment.disposition = OSProbeDisposition::Matching;
            assessment.response_behavior = ResponseBehavior::NoResponse;
            return assessment;
        }
        if (!response.source_address.empty() && response.source_address != submission.target) {
            return assessment;
        }
        if (!response.destination_address.empty() && response.destination_address != submission.source_address) {
            return assessment;
        }
        if (submission.type == OSProbeType::IcmpEcho) {
            const auto icmp = packet::ICMP::parse(response.bytes);
            if (!icmp.has_value()) {
                assessment.status = core::StatusCode::ParseError;
                assessment.disposition = OSProbeDisposition::Malformed;
                assessment.response_behavior = ResponseBehavior::Malformed;
                return assessment;
            }
            if (icmp->type() != packet::IcmpType::EchoReply ||
                icmp->identifier() != submission.correlation_identifier ||
                icmp->sequence() != submission.correlation_sequence) {
                return assessment;
            }
            assessment.disposition = OSProbeDisposition::Matching;
            assessment.response_behavior = ResponseBehavior::EchoReply;
            ICMPObservation observation;
            observation.ttl = response.ip_ttl == 0U ? ObservedValue<std::uint8_t>::absent()
                                                     : ObservedValue<std::uint8_t>::observed(response.ip_ttl);
            observation.type = ObservedValue<std::uint8_t>::observed(static_cast<std::uint8_t>(icmp->type()));
            observation.code = ObservedValue<std::uint8_t>::observed(icmp->code());
            observation.response_behavior = assessment.response_behavior;
            observation.probe_status = OSProbeStatus::ResponseReceived;
            assessment.icmp_observation = std::move(observation);
            return assessment;
        }
        if (submission.type == OSProbeType::UdpFingerprint || submission.type == OSProbeType::UdpPortUnreachable) {
            const auto destination = discovery::parse_ipv4_address(submission.target);
            const auto source = discovery::parse_ipv4_address(submission.source_address);
            if (!destination.has_value() || !source.has_value()) {
                assessment.status = core::StatusCode::InvalidArgument;
                assessment.disposition = OSProbeDisposition::Malformed;
                assessment.response_behavior = ResponseBehavior::Malformed;
                return assessment;
            }
            UDPObservation observation;
            observation.ttl = response.ip_ttl == 0U ? ObservedValue<std::uint8_t>::absent()
                                                     : ObservedValue<std::uint8_t>::observed(response.ip_ttl);
            observation.ip_identification = response.ip_identification == 0U
                                                ? ObservedValue<std::uint16_t>::absent()
                                                : ObservedValue<std::uint16_t>::observed(response.ip_identification);
            observation.dont_fragment = response.ip_dont_fragment
                                             ? ObservedValue<bool>::observed(true)
                                             : ObservedValue<bool>::absent();
            observation.probe_status = OSProbeStatus::ResponseReceived;
            if (response.kind == OSProbeResponseKind::IcmpError) {
                const auto icmp = packet::ICMP::parse(response.bytes);
                if (!icmp.has_value() || icmp->type() != packet::IcmpType::DestinationUnreachable ||
                    icmp->payload().size() < packet::IPv4::kMinimumHeaderSize + packet::UDP::kHeaderSize) {
                    assessment.status = core::StatusCode::ParseError;
                    assessment.disposition = OSProbeDisposition::Malformed;
                    assessment.response_behavior = ResponseBehavior::Malformed;
                    return assessment;
                }
                const std::span<const std::uint8_t> quoted{icmp->payload()};
                const std::uint8_t ihl = static_cast<std::uint8_t>(quoted[0] & 0x0FU);
                const std::size_t header_size = static_cast<std::size_t>(ihl) * 4U;
                if ((quoted[0] >> 4U) != 4U || ihl < 5U || quoted.size() < header_size + packet::UDP::kHeaderSize ||
                    packet::checksum::internet(quoted.first(header_size)) != 0U || quoted[9] != 17U) {
                    assessment.status = core::StatusCode::ParseError;
                    assessment.disposition = OSProbeDisposition::Malformed;
                    assessment.response_behavior = ResponseBehavior::Malformed;
                    return assessment;
                }
                const std::uint16_t udp_length = packet::wire::read_u16(quoted, header_size + 4U);
                if (udp_length < packet::UDP::kHeaderSize || packet::wire::read_u32(quoted, 12U) != *source ||
                    packet::wire::read_u32(quoted, 16U) != *destination ||
                    packet::wire::read_u16(quoted, header_size) != submission.source_port ||
                    packet::wire::read_u16(quoted, header_size + 2U) != submission.destination_port) {
                    return assessment;
                }
                assessment.disposition = OSProbeDisposition::Matching;
                assessment.response_behavior = icmp->code() == 3U ? ResponseBehavior::PortUnreachable
                                                                    : ResponseBehavior::Malformed;
                observation.response_behavior = assessment.response_behavior;
                assessment.udp_observation = std::move(observation);
                return assessment;
            }
            const auto udp = packet::UDP::parse(response.bytes);
            if (!udp.has_value() || udp->source_port() != submission.destination_port ||
                udp->destination_port() != submission.source_port) {
                assessment.status = core::StatusCode::ParseError;
                assessment.disposition = OSProbeDisposition::Malformed;
                assessment.response_behavior = ResponseBehavior::Malformed;
                return assessment;
            }
            assessment.disposition = OSProbeDisposition::Matching;
            assessment.response_behavior = ResponseBehavior::UdpResponse;
            observation.source_port = udp->source_port();
            observation.destination_port = udp->destination_port();
            observation.payload_length = ObservedValue<std::size_t>::observed(udp->payload().size());
            observation.response_behavior = ResponseBehavior::UdpResponse;
            assessment.udp_observation = std::move(observation);
            return assessment;
        }
        if (response.bytes.size() < packet::IPv4::kMinimumHeaderSize) {
            assessment.status = core::StatusCode::ParseError;
            assessment.disposition = OSProbeDisposition::Malformed;
            assessment.response_behavior = ResponseBehavior::Malformed;
            return assessment;
        }
        const auto ip = packet::IPv4::parse(response.bytes);
        if (!ip.has_value() || ip->protocol() != 6U) {
            assessment.status = core::StatusCode::ParseError;
            assessment.disposition = OSProbeDisposition::Malformed;
            assessment.response_behavior = ResponseBehavior::Malformed;
            return assessment;
        }
        const std::size_t header_size = static_cast<std::size_t>(ip->ihl()) * 4U;
        if (header_size > response.bytes.size()) {
            assessment.status = core::StatusCode::ParseError;
            assessment.disposition = OSProbeDisposition::Malformed;
            assessment.response_behavior = ResponseBehavior::Malformed;
            return assessment;
        }
        const auto tcp = packet::TCP::parse(std::span<const std::uint8_t>{response.bytes}.subspan(header_size));
        if (!tcp.has_value()) {
            assessment.status = core::StatusCode::ParseError;
            assessment.disposition = OSProbeDisposition::Malformed;
            assessment.response_behavior = ResponseBehavior::Malformed;
            return assessment;
        }
        const auto destination = discovery::parse_ipv4_address(submission.target);
        const auto source = discovery::parse_ipv4_address(submission.source_address);
        if (!destination.has_value() || !source.has_value() || ip->source_address() != *destination ||
            ip->destination_address() != *source || tcp->source_port() != submission.destination_port ||
            tcp->destination_port() != submission.source_port) {
            return assessment;
        }
        const bool is_rst = packet::has_flag(tcp->flags(), packet::TcpFlag::Rst);
        const bool is_syn_ack = packet::has_flag(tcp->flags(), packet::TcpFlag::Syn) &&
                                packet::has_flag(tcp->flags(), packet::TcpFlag::Ack) &&
                                tcp->acknowledgment_number() == submission.sequence_number + 1U;
        if (!is_rst && !is_syn_ack) {
            return assessment;
        }
        assessment.disposition = OSProbeDisposition::Matching;
        assessment.response_behavior = is_rst ? ResponseBehavior::Rst : ResponseBehavior::SynAck;
        assessment.tcp_observation = observe_tcp_response(
            submission.target,
            submission.source_address,
            *ip,
            *tcp,
            assessment.response_behavior);
        return assessment;
    }

private:
    OSProbeType type_;
};

} // namespace

std::unique_ptr<OSProbe> make_os_probe(OSProbeType type)
{
    if (type == OSProbeType::UdpPortUnreachable) {
        return std::make_unique<DefinedOSProbe>(type);
    }
    return std::make_unique<DefinedOSProbe>(type);
}

bool RecordingOSProbeTransport::supports(OSProbeType) const noexcept
{
    return true;
}

core::StatusCode RecordingOSProbeTransport::submit(OSProbeSubmission submission, OSProbeCallback callback)
{
    if (submission.id == 0U || callback == nullptr || callbacks_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    try {
        submissions_.push_back(submission);
        const auto inserted = callbacks_.emplace(submission.id, std::move(callback));
        if (!inserted.second) {
            submissions_.pop_back();
            return core::StatusCode::InvalidArgument;
        }
    } catch (const std::bad_alloc &) {
        if (!submissions_.empty() && submissions_.back().id == submission.id) {
            submissions_.pop_back();
        }
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode RecordingOSProbeTransport::cancel(OSProbeId id) noexcept
{
    callbacks_.erase(id);
    return core::StatusCode::Ok;
}

void RecordingOSProbeTransport::deliver(OSProbeResponse response)
{
    const auto iterator = callbacks_.find(response.id);
    if (iterator == callbacks_.end()) {
        return;
    }
    OSProbeCallback callback = iterator->second;
    if (response.received_at == OSProbeTimePoint{}) {
        response.received_at = OSProbeClock::now();
    }
    callback(response);
}

const std::vector<OSProbeSubmission> &RecordingOSProbeTransport::submissions() const noexcept
{
    return submissions_;
}

bool live_os_fingerprinting_available() noexcept
{
    return true;
}

} // namespace skan::osdetect
