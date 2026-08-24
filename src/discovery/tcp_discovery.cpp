#include "discovery/tcp_discovery.hpp"

#include <cstdint>

#include "packet/tcp.hpp"

namespace skan::discovery {

ProbeType TcpDiscoveryProbe::type() const noexcept
{
    return ProbeType::Tcp;
}

core::StatusCode TcpDiscoveryProbe::build(
    ProbeId id,
    const core::Host &target,
    const DiscoveryConfig &config,
    ProbeSubmission &submission) const
{
    const auto target_ipv4 = parse_ipv4_address(target.address);
    if (!target_ipv4.has_value() || id == 0U || config.tcp_port == 0U || id > 0xFFFFU) {
        return core::StatusCode::InvalidArgument;
    }

    const std::uint16_t source_port = static_cast<std::uint16_t>(40000U + ((id - 1U) % 20000U));
    const std::uint32_t sequence_number = 0x534B0000U | static_cast<std::uint32_t>(id);
    skan::packet::TCP syn;
    syn.set_source_port(source_port);
    syn.set_destination_port(config.tcp_port);
    syn.set_sequence_number(sequence_number);
    syn.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Syn));
    syn.set_window(64240U);

    submission = ProbeSubmission{};
    submission.id = id;
    submission.type = type();
    submission.target = target.address;
    submission.port = config.tcp_port;
    submission.source_port = source_port;
    submission.sequence_number = sequence_number;
    submission.target_ipv4 = *target_ipv4;
    submission.packet.resize(syn.serialized_size(), 0U);
    if (syn.serialize_with_checksum(submission.packet, 0U, submission.target_ipv4) != core::StatusCode::Ok) {
        return core::StatusCode::InternalError;
    }
    return core::StatusCode::Ok;
}

ResponseDisposition TcpDiscoveryProbe::assess(
    const DiscoveryResponse &response,
    const ProbeSubmission &submission) const
{
    const auto parsed = skan::packet::TCP::parse(std::span<const std::uint8_t>{response.bytes});
    if (!parsed.has_value()) {
        return ResponseDisposition::Malformed;
    }
    if (response.source_address != submission.target ||
        parsed->source_port() != submission.port ||
        parsed->destination_port() != submission.source_port) {
        return ResponseDisposition::Unrelated;
    }

    const bool syn_ack = skan::packet::has_flag(parsed->flags(), skan::packet::TcpFlag::Syn) &&
                         skan::packet::has_flag(parsed->flags(), skan::packet::TcpFlag::Ack) &&
                         parsed->acknowledgment_number() == submission.sequence_number + 1U;
    const bool rst = skan::packet::has_flag(parsed->flags(), skan::packet::TcpFlag::Rst);
    return (syn_ack || rst) ? ResponseDisposition::Matching : ResponseDisposition::Unrelated;
}

DiscoveryReason TcpDiscoveryProbe::positive_reason(const DiscoveryResponse &response) const noexcept
{
    const auto parsed = skan::packet::TCP::parse(std::span<const std::uint8_t>{response.bytes});
    if (parsed.has_value() && skan::packet::has_flag(parsed->flags(), skan::packet::TcpFlag::Rst)) {
        return DiscoveryReason::TcpRst;
    }
    return DiscoveryReason::TcpSynAck;
}

} // namespace skan::discovery
