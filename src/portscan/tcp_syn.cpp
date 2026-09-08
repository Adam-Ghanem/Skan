#include "portscan/tcp_syn.hpp"

#include <cerrno>
#include <limits>
#include <optional>

namespace skan::portscan {
namespace {

bool is_advanced_raw_tcp_probe(ScanProbeType type) noexcept
{
    return is_raw_tcp_probe(type) && type != ScanProbeType::TcpSyn;
}

std::optional<std::uint16_t> advanced_flags(ScanProbeType type) noexcept
{
    switch (type) {
    case ScanProbeType::TcpNull:
        return 0U;
    case ScanProbeType::TcpFin:
        return static_cast<std::uint16_t>(packet::TcpFlag::Fin);
    case ScanProbeType::TcpXmas:
        return static_cast<std::uint16_t>(packet::TcpFlag::Fin) |
               static_cast<std::uint16_t>(packet::TcpFlag::Psh) |
               static_cast<std::uint16_t>(packet::TcpFlag::Urg);
    case ScanProbeType::TcpWindow:
        return static_cast<std::uint16_t>(packet::TcpFlag::Ack);
    case ScanProbeType::TcpMaimon:
        return static_cast<std::uint16_t>(packet::TcpFlag::Fin) |
               static_cast<std::uint16_t>(packet::TcpFlag::Ack);
    case ScanProbeType::TcpConnect:
    case ScanProbeType::TcpSyn:
    case ScanProbeType::Udp:
        return std::nullopt;
    }
    return std::nullopt;
}

bool response_source_matches(const PortResponse &response, const PortSubmission &submission) noexcept
{
    if (response.source_ip.valid()) {
        return submission.target_ip.valid() && response.source_ip == submission.target_ip;
    }
    return response.source_address == submission.target;
}

} // namespace

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
    if (response.id != submission.id) {
        return core::StatusCode::NotFound;
    }
    if (response.kind == PortResponseKind::Unreachable) {
        if (response.source_ip.valid() && submission.target_ip.valid() && response.source_ip != submission.target_ip) {
            return core::StatusCode::NotFound;
        }
        state = PortState::Unreachable;
        reason = ScanReason::NetworkUnreachable;
        return core::StatusCode::Ok;
    }
    if (response.kind != PortResponseKind::Packet) {
        return core::StatusCode::NotFound;
    }
    if (!response_source_matches(response, submission)) {
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

TcpFlagProbe::TcpFlagProbe(ScanProbeType type) noexcept
    : type_(type)
{
}

ScanProbeType TcpFlagProbe::type() const noexcept
{
    return type_;
}

core::StatusCode TcpFlagProbe::build(
    PortProbeId id,
    const core::Host &target,
    const Port &port,
    const PortScanConfig &config,
    PortSubmission &submission) const
{
    const auto flags = advanced_flags(type_);
    if (!flags.has_value() || config.method != type_ || id == 0U || port.protocol != Protocol::Tcp ||
        port.number == 0U || target.address.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    const auto target_ip = target.ip_address.valid() ? std::optional<core::IpAddress>{target.ip_address}
                                                       : core::parse_ip_address(target.address);
    if (!target_ip.has_value()) {
        return core::StatusCode::InvalidArgument;
    }

    packet::TCP tcp;
    tcp.set_source_port(TcpSynProbe::source_port_for(id));
    tcp.set_destination_port(port.number);
    tcp.set_sequence_number(TcpSynProbe::sequence_for(id));
    const bool sends_ack = packet::has_flag(*flags, packet::TcpFlag::Ack);
    tcp.set_acknowledgment_number(sends_ack ? (TcpSynProbe::sequence_for(id) ^ 0xA5A5A5A5U) : 0U);
    tcp.set_flags(*flags);
    tcp.set_window(65535U);

    submission = PortSubmission{};
    submission.id = id;
    submission.probe = type_;
    submission.target = target.address;
    submission.port = port;
    submission.source_port = TcpSynProbe::source_port_for(id);
    submission.sequence_number = TcpSynProbe::sequence_for(id);
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

PortState TcpFlagProbe::timeout_state() const noexcept
{
    if (type_ == ScanProbeType::TcpWindow) {
        return PortState::Filtered;
    }
    if (is_advanced_raw_tcp_probe(type_)) {
        return PortState::OpenOrFiltered;
    }
    return PortState::Unknown;
}

ScanReason TcpFlagProbe::timeout_reason() const noexcept
{
    return ScanReason::Timeout;
}

core::StatusCode TcpFlagProbe::assess(
    const PortResponse &response,
    const PortSubmission &submission,
    PortState &state,
    ScanReason &reason) const
{
    if (!is_advanced_raw_tcp_probe(type_) || submission.probe != type_ || response.id != submission.id) {
        return core::StatusCode::NotFound;
    }
    if (response.kind == PortResponseKind::Unreachable) {
        if (response.source_ip.valid() && submission.target_ip.valid() && response.source_ip != submission.target_ip) {
            return core::StatusCode::NotFound;
        }
        state = PortState::Unreachable;
        reason = ScanReason::NetworkUnreachable;
        return core::StatusCode::Ok;
    }
    if (response.kind != PortResponseKind::Packet || !response_source_matches(response, submission)) {
        return core::StatusCode::NotFound;
    }
    const auto parsed = packet::TCP::parse(response.bytes);
    if (!parsed.has_value()) {
        return core::StatusCode::ParseError;
    }
    const packet::TCP &tcp = *parsed;
    if (tcp.source_port() != submission.port.number || tcp.destination_port() != submission.source_port ||
        !packet::has_flag(tcp.flags(), packet::TcpFlag::Rst)) {
        return core::StatusCode::NotFound;
    }

    if (type_ == ScanProbeType::TcpWindow) {
        if (tcp.window() != 0U) {
            state = PortState::Open;
            reason = ScanReason::RstWindowOpen;
        } else {
            state = PortState::Closed;
            reason = ScanReason::RstWindowZero;
        }
        return core::StatusCode::Ok;
    }

    state = PortState::Closed;
    reason = ScanReason::Rst;
    return core::StatusCode::Ok;
}

bool tcp_syn_network_capability_available() noexcept
{
    return false;
}

} // namespace skan::portscan
