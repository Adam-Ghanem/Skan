#include "osdetect/os_fingerprint.hpp"

#include <utility>

namespace skan::osdetect {
namespace {

bool has_option(const packet::TCP &tcp, packet::TcpOptionKind kind) noexcept
{
    for (const packet::TcpOption &option : tcp.options()) {
        if (option.kind == kind) {
            return true;
        }
    }
    return false;
}

std::optional<std::uint16_t> option_value(const packet::TCP &tcp, packet::TcpOptionKind kind) noexcept
{
    for (const packet::TcpOption &option : tcp.options()) {
        if (option.kind == kind) {
            return option.value;
        }
    }
    return std::nullopt;
}

} // namespace

TCPObservation observe_tcp_response(
    std::string source_address,
    std::string destination_address,
    const packet::IPv4 &ip,
    const packet::TCP &tcp,
    ResponseBehavior response_behavior,
    OSProbeStatus probe_status)
{
    TCPObservation observation;
    observation.source_address = std::move(source_address);
    observation.destination_address = std::move(destination_address);
    observation.source_port = tcp.source_port();
    observation.destination_port = tcp.destination_port();
    observation.ttl = ObservedValue<std::uint8_t>::observed(ip.ttl());
    observation.dont_fragment = ObservedValue<bool>::observed(
        (ip.flags_fragment_offset() & 0x4000U) != 0U);
    observation.window = ObservedValue<std::uint16_t>::observed(tcp.window());
    observation.flags = tcp.flags();
    observation.sequence_number = ObservedValue<std::uint32_t>::observed(tcp.sequence_number());
    observation.acknowledgment_number =
        ObservedValue<std::uint32_t>::observed(tcp.acknowledgment_number());
    observation.payload_length = tcp.payload().size();
    observation.response_behavior = response_behavior;
    observation.probe_status = probe_status;

    for (const packet::TcpOption &option : tcp.options()) {
        observation.options.push_back(option.kind);
    }
    if (const auto value = option_value(tcp, packet::TcpOptionKind::Mss); value.has_value()) {
        observation.mss = ObservedValue<std::uint16_t>::observed(*value);
    }
    if (const auto value = option_value(tcp, packet::TcpOptionKind::WindowScale); value.has_value()) {
        observation.window_scale = ObservedValue<std::uint8_t>::observed(static_cast<std::uint8_t>(*value));
    }
    observation.sack_permitted = ObservedValue<bool>::observed(
        has_option(tcp, packet::TcpOptionKind::SackPermitted));
    const bool has_timestamp = has_option(tcp, packet::TcpOptionKind::Timestamp);
    observation.timestamps = ObservedValue<bool>::observed(has_timestamp);
    observation.timestamp_behavior = has_timestamp ? TimestampBehavior::Present
                                                    : TimestampBehavior::Absent;

    if (packet::has_flag(tcp.flags(), packet::TcpFlag::Ack)) {
        observation.ack_behavior = AckBehavior::AcknowledgesSyn;
    } else if (packet::has_flag(tcp.flags(), packet::TcpFlag::Rst)) {
        observation.ack_behavior = AckBehavior::RstWithoutAck;
    } else {
        observation.ack_behavior = AckBehavior::NoAck;
    }
    return observation;
}

ICMPObservation observe_icmp_response(
    const packet::IPv4 &ip,
    std::uint8_t type,
    std::uint8_t code,
    ResponseBehavior response_behavior,
    OSProbeStatus probe_status)
{
    ICMPObservation observation;
    observation.ttl = ObservedValue<std::uint8_t>::observed(ip.ttl());
    observation.type = ObservedValue<std::uint8_t>::observed(type);
    observation.code = ObservedValue<std::uint8_t>::observed(code);
    observation.response_behavior = response_behavior;
    observation.probe_status = probe_status;
    return observation;
}

void append_observation(ObservedOSFingerprint &fingerprint, TCPObservation observation)
{
    switch (observation.probe_status) {
    case OSProbeStatus::Generated:
        ++fingerprint.probes_generated;
        break;
    case OSProbeStatus::Sent:
        ++fingerprint.probes_sent;
        break;
    case OSProbeStatus::ResponseReceived:
        ++fingerprint.responses_received;
        break;
    case OSProbeStatus::Timeout:
        ++fingerprint.probes_timed_out;
        break;
    case OSProbeStatus::Unsupported:
        ++fingerprint.probes_unsupported;
        break;
    case OSProbeStatus::Malformed:
        ++fingerprint.probes_malformed;
        break;
    }
    fingerprint.tcp_observations.push_back(std::move(observation));
    fingerprint.timestamp = std::chrono::steady_clock::now();
}

void append_observation(ObservedOSFingerprint &fingerprint, UDPObservation observation)
{
    switch (observation.probe_status) {
    case OSProbeStatus::Generated:
        ++fingerprint.probes_generated;
        break;
    case OSProbeStatus::Sent:
        ++fingerprint.probes_sent;
        break;
    case OSProbeStatus::ResponseReceived:
        ++fingerprint.responses_received;
        break;
    case OSProbeStatus::Timeout:
        ++fingerprint.probes_timed_out;
        break;
    case OSProbeStatus::Unsupported:
        ++fingerprint.probes_unsupported;
        break;
    case OSProbeStatus::Malformed:
        ++fingerprint.probes_malformed;
        break;
    }
    fingerprint.udp_observations.push_back(std::move(observation));
    fingerprint.timestamp = std::chrono::steady_clock::now();
}

void append_observation(ObservedOSFingerprint &fingerprint, ICMPObservation observation)
{
    switch (observation.probe_status) {
    case OSProbeStatus::Generated:
        ++fingerprint.probes_generated;
        break;
    case OSProbeStatus::Sent:
        ++fingerprint.probes_sent;
        break;
    case OSProbeStatus::ResponseReceived:
        ++fingerprint.responses_received;
        break;
    case OSProbeStatus::Timeout:
        ++fingerprint.probes_timed_out;
        break;
    case OSProbeStatus::Unsupported:
        ++fingerprint.probes_unsupported;
        break;
    case OSProbeStatus::Malformed:
        ++fingerprint.probes_malformed;
        break;
    }
    fingerprint.icmp_observations.push_back(std::move(observation));
    fingerprint.timestamp = std::chrono::steady_clock::now();
}

} // namespace skan::osdetect
