#include "discovery/tcp_discovery.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <string>

#include "packet/tcp.hpp"

namespace skan::discovery {
namespace {

std::optional<core::IpAddress> parse_ip(std::string_view text) noexcept
{
    const std::string value(text);
    in_addr ipv4{};
    if (::inet_pton(AF_INET, value.c_str(), &ipv4) == 1) {
        return core::IpAddress::from_ipv4(ntohl(ipv4.s_addr));
    }
    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, value.c_str(), &ipv6) == 1) {
        std::array<std::uint8_t, 16U> bytes{};
        std::copy(std::begin(ipv6.s6_addr), std::end(ipv6.s6_addr), bytes.begin());
        return core::IpAddress::from_ipv6(bytes);
    }
    return std::nullopt;
}

} // namespace

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
    const auto target_ip = target.ip_address.valid() ? std::optional<core::IpAddress>{target.ip_address}
                                                     : parse_ip(target.address);
    if (!target_ip.has_value() || id == 0U || config.tcp_port == 0U || id > 0xFFFFU) {
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
    submission.target_ip = *target_ip;
    submission.packet.resize(syn.serialized_size(), 0U);
    if (target_ip->is_ipv4()) {
        submission.target_ipv4 = (static_cast<std::uint32_t>(target_ip->bytes[0]) << 24U) |
                                 (static_cast<std::uint32_t>(target_ip->bytes[1]) << 16U) |
                                 (static_cast<std::uint32_t>(target_ip->bytes[2]) << 8U) |
                                 static_cast<std::uint32_t>(target_ip->bytes[3]);
        if (syn.serialize_with_checksum(submission.packet, 0U, submission.target_ipv4) != core::StatusCode::Ok) {
            return core::StatusCode::InternalError;
        }
    } else {
        const std::array<std::uint8_t, 16U> unspecified{};
        submission.source_ip = core::IpAddress::from_ipv6(unspecified);
        if (syn.serialize_with_checksum(submission.packet, unspecified, target_ip->bytes) != core::StatusCode::Ok) {
            return core::StatusCode::InternalError;
        }
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
