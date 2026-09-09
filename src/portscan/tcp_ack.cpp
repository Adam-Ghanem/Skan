#include "portscan/tcp_ack.hpp"

#include <array>
#include <new>
#include <optional>

namespace skan::portscan {

ScanProbeType TcpAckProbe::type() const noexcept
{
    return ScanProbeType::TcpAck;
}

std::uint16_t TcpAckProbe::source_port_for(PortProbeId id) noexcept
{
    return static_cast<std::uint16_t>(40000U + (id % 20000U));
}

std::uint32_t TcpAckProbe::sequence_for(PortProbeId id) noexcept
{
    std::uint32_t value = static_cast<std::uint32_t>(id);
    value ^= 0x7f4a7c15U;
    value *= 1664525U;
    value += 1013904223U;
    return value == 0U ? 1U : value;
}

std::uint32_t TcpAckProbe::acknowledgment_for(PortProbeId id) noexcept
{
    std::uint32_t value = static_cast<std::uint32_t>(id);
    value ^= 0x85ebca6bU;
    value *= 2246822519U;
    value += 3266489917U;
    return value == 0U ? 1U : value;
}

core::StatusCode TcpAckProbe::build(
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
    tcp.set_acknowledgment_number(acknowledgment_for(id));
    tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Ack));
    tcp.set_window(65535U);

    submission = PortSubmission{};
    submission.id = id;
    submission.probe = type();
    submission.target = target.address;
    submission.port = port;
    submission.source_port = source_port_for(id);
    submission.sequence_number = sequence_for(id);
    submission.acknowledgment_number = acknowledgment_for(id);
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

PortState TcpAckProbe::timeout_state() const noexcept
{
    return PortState::Filtered;
}

ScanReason TcpAckProbe::timeout_reason() const noexcept
{
    return ScanReason::AckTimeout;
}

core::StatusCode TcpAckProbe::assess(
    const PortResponse &response,
    const PortSubmission &submission,
    PortState &state,
    ScanReason &reason) const
{
    if (response.id != submission.id || submission.probe != type()) {
        return core::StatusCode::NotFound;
    }
    if (response.kind == PortResponseKind::Unreachable) {
        if (response.source_ip.valid()
                ? (!submission.target_ip.valid() || response.source_ip != submission.target_ip)
                : response.source_address != submission.target) {
            return core::StatusCode::NotFound;
        }
        state = PortState::Filtered;
        reason = ScanReason::IcmpNetworkUnreachable;
        return core::StatusCode::Ok;
    }
    if (response.kind != PortResponseKind::Packet) {
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
    if (!packet::has_flag(flags, packet::TcpFlag::Rst) ||
        packet::has_flag(flags, packet::TcpFlag::Ack) ||
        packet::has_flag(flags, packet::TcpFlag::Syn) ||
        packet::has_flag(flags, packet::TcpFlag::Fin) ||
        tcp.sequence_number() != submission.acknowledgment_number) {
        return core::StatusCode::NotFound;
    }
    state = PortState::Unfiltered;
    reason = ScanReason::AckRst;
    return core::StatusCode::Ok;
}

} // namespace skan::portscan
