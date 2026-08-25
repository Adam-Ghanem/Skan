#include "discovery/icmp_discovery.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "packet/icmp.hpp"
#include "packet/icmpv6.hpp"

namespace skan::discovery {
namespace {

std::optional<core::IpAddress> parse_ip(std::string_view text) noexcept
{
    in_addr ipv4{};
    const std::string value(text);
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

ProbeType IcmpDiscoveryProbe::type() const noexcept
{
    return ProbeType::IcmpEcho;
}

core::StatusCode IcmpDiscoveryProbe::build(
    ProbeId id,
    const core::Host &target,
    const DiscoveryConfig &config,
    ProbeSubmission &submission) const
{
    (void)config;
    const auto target_ip = target.ip_address.valid() ? std::optional<core::IpAddress>{target.ip_address}
                                                     : parse_ip(target.address);
    if (!target_ip.has_value() || id == 0U || id > 0xFFFFU) {
        return core::StatusCode::InvalidArgument;
    }

    submission = ProbeSubmission{};
    submission.id = id;
    submission.type = type();
    submission.target = target.address;
    submission.correlation_identifier = 0x534BU;
    submission.correlation_sequence = static_cast<std::uint16_t>(id);
    submission.target_ip = *target_ip;
    if (target_ip->is_ipv4()) {
        skan::packet::ICMP echo(skan::packet::IcmpType::EchoRequest);
        echo.set_identifier(submission.correlation_identifier);
        echo.set_sequence(submission.correlation_sequence);
        echo.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
        submission.packet = echo.serialize();
        submission.target_ipv4 = (static_cast<std::uint32_t>(target_ip->bytes[0]) << 24U) |
                                 (static_cast<std::uint32_t>(target_ip->bytes[1]) << 16U) |
                                 (static_cast<std::uint32_t>(target_ip->bytes[2]) << 8U) |
                                 static_cast<std::uint32_t>(target_ip->bytes[3]);
    } else {
        skan::packet::ICMPv6 echo(skan::packet::Icmpv6Type::EchoRequest);
        echo.set_identifier(submission.correlation_identifier);
        echo.set_sequence(submission.correlation_sequence);
        echo.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
        const std::array<std::uint8_t, 16U> unspecified{};
        submission.packet.resize(echo.serialized_size(), 0U);
        if (echo.serialize_with_checksum(submission.packet, unspecified, target_ip->bytes) != core::StatusCode::Ok) {
            return core::StatusCode::InternalError;
        }
        submission.source_ip = core::IpAddress::from_ipv6(unspecified);
    }
    return submission.packet.empty() ? core::StatusCode::InternalError : core::StatusCode::Ok;
}

ResponseDisposition IcmpDiscoveryProbe::assess(
    const DiscoveryResponse &response,
    const ProbeSubmission &submission) const
{
    if (submission.target_ip.is_ipv6()) {
        const auto parsed = skan::packet::ICMPv6::parse(std::span<const std::uint8_t>{response.bytes});
        const auto source = parse_ip(response.source_address);
        if (!parsed.has_value() || !source.has_value() || *source != submission.target_ip) {
            return parsed.has_value() ? ResponseDisposition::Unrelated : ResponseDisposition::Malformed;
        }
        if (parsed->type() != skan::packet::Icmpv6Type::EchoReply || parsed->code() != 0U ||
            parsed->identifier() != submission.correlation_identifier ||
            parsed->sequence() != submission.correlation_sequence) {
            return ResponseDisposition::Unrelated;
        }
        return ResponseDisposition::Matching;
    }
    const auto parsed = skan::packet::ICMP::parse(std::span<const std::uint8_t>{response.bytes});
    if (!parsed.has_value()) {
        return ResponseDisposition::Malformed;
    }
    if (response.source_address != submission.target) {
        return ResponseDisposition::Unrelated;
    }
    if (parsed->type() != skan::packet::IcmpType::EchoReply || parsed->code() != 0U ||
        parsed->identifier() != submission.correlation_identifier ||
        parsed->sequence() != submission.correlation_sequence) {
        return ResponseDisposition::Unrelated;
    }
    return ResponseDisposition::Matching;
}

DiscoveryReason IcmpDiscoveryProbe::positive_reason(const DiscoveryResponse &response) const noexcept
{
    (void)response;
    return DiscoveryReason::IcmpEchoReply;
}

} // namespace skan::discovery
