#include "discovery/icmp_discovery.hpp"

#include <cstdint>
#include <utility>

#include "packet/icmp.hpp"

namespace skan::discovery {

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
    if (!parse_ipv4_address(target.address).has_value() || id == 0U || id > 0xFFFFU) {
        return core::StatusCode::InvalidArgument;
    }

    skan::packet::ICMP echo(skan::packet::IcmpType::EchoRequest);
    echo.set_identifier(0x534BU);
    echo.set_sequence(static_cast<std::uint16_t>(id));
    echo.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});

    submission = ProbeSubmission{};
    submission.id = id;
    submission.type = type();
    submission.target = target.address;
    submission.packet = echo.serialize();
    submission.correlation_identifier = echo.identifier();
    submission.correlation_sequence = echo.sequence();
    submission.target_ipv4 = *parse_ipv4_address(target.address);
    return core::StatusCode::Ok;
}

ResponseDisposition IcmpDiscoveryProbe::assess(
    const DiscoveryResponse &response,
    const ProbeSubmission &submission) const
{
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
