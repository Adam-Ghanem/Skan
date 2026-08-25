#include "portscan/tcp_syn.hpp"

#include <cerrno>
#include <limits>

namespace skan::portscan {

ScanProbeType TcpSynProbe::type() const noexcept
{
    return ScanProbeType::TcpSyn;
}

std::uint16_t TcpSynProbe::source_port_for(PortProbeId id) noexcept
{
    return static_cast<std::uint16_t>(40000U + (id % 20000U));
}

std::uint32_t TcpSynProbe::sequence_for(PortProbeId id) noexcept
{
    std::uint32_t value = static_cast<std::uint32_t>(id);
    value ^= 0x9e3779b9U;
    value *= 1664525U;
    value += 1013904223U;
    return value;
}

core::StatusCode TcpSynProbe::build(
    PortProbeId id,
    const core::Host &target,
    const Port &port,
    const PortScanConfig &config,
    PortSubmission &submission) const
{
    (void)config;
    if (id == 0U || port.protocol != Protocol::Tcp || port.number == 0U || target.address.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    const auto target_ip = target.ip_address.valid() ? std::optional<core::IpAddress>{target.ip_address}
                                                       : core::parse_ip_address(target.address);
    if (!target_ip.has_value()) {
        return core::StatusCode::InvalidArgument;
    }

    packet::TCP tcp;
    tcp.set_source_port(source_port_for(id));
    tcp.set_destination_port(port.number);
    tcp.set_sequence_number(sequence_for(id));
    tcp.set_acknowledgment_number(0U);
    tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Syn));
    tcp.set_window(65535U);
    submission = PortSubmission{};
    submission.id = id;
    submission.probe = type();
    submission.target = target.address;
    submission.port = port;
    submission.source_port = source_port_for(id);
    submission.sequence_number = sequence_for(id);
    submission.target_ip = *target_ip;
    try {
        submission.packet.resize(tcp.serialized_size());
    } catch (const std::bad_alloc &) {
        return core::StatusCode::MemoryError;
    }
    if (target_ip->is_ipv6()) {
        return tcp.serialize_with_checksum(submission.packet, std::array<std::uint8_t, 16U>{}, target_ip->bytes);
    }
    return tcp.serialize(submission.packet);
}

PortState TcpSynProbe::timeout_state() const noexcept
{
    return PortState::Filtered;
}

ScanReason TcpSynProbe::timeout_reason() const noexcept
{
    return ScanReason::Timeout;
}

core::StatusCode TcpSynProbe::assess(
    const PortResponse &response,
    const PortSubmission &submission,
    PortState &state,
    ScanReason &reason) const
{
    if (response.id != submission.id || response.kind != PortResponseKind::Packet) {
        return core::StatusCode::NotFound;
    }
    if (response.source_ip.valid()) {
        if (!submission.target_ip.valid() || response.source_ip != submission.target_ip) {
            return core::StatusCode::NotFound;
        }
    } else if (response.source_address != submission.target) {
        return core::StatusCode::NotFound;
    }
    const auto parsed = packet::TCP::parse(response.bytes);
    if (!parsed.has_value()) {
        return core::StatusCode::ParseError;
    }
    const packet::TCP &tcp = *parsed;
    if (tcp.source_port() != submission.port.number || tcp.destination_port() != submission.source_port) {
        return core::StatusCode::NotFound;
    }
    const std::uint16_t flags = tcp.flags();
    const bool has_ack = packet::has_flag(flags, packet::TcpFlag::Ack);
    if (packet::has_flag(flags, packet::TcpFlag::Syn) && has_ack &&
        tcp.acknowledgment_number() == submission.sequence_number + 1U) {
        state = PortState::Open;
        reason = ScanReason::SynAck;
        return core::StatusCode::Ok;
    }
    if (packet::has_flag(flags, packet::TcpFlag::Rst) &&
        (!has_ack || tcp.acknowledgment_number() == submission.sequence_number + 1U)) {
        state = PortState::Closed;
        reason = ScanReason::Rst;
        return core::StatusCode::Ok;
    }
    return core::StatusCode::NotFound;
}

bool tcp_syn_network_capability_available() noexcept
{
    return false;
}

} // namespace skan::portscan
