#include <cassert>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "discovery/discovery_types.hpp"
#include "osdetect/os_probe.hpp"
#include "packet/icmp.hpp"
#include "packet/icmpv6.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

namespace {

std::vector<std::uint8_t> tcp_response(
    const skan::osdetect::OSProbeSubmission &submission,
    std::uint32_t source_address,
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint16_t flags,
    std::uint32_t acknowledgment_number,
    std::uint8_t ttl = 64U)
{
    using namespace skan;
    const auto destination = discovery::parse_ipv4_address(submission.source_address);
    assert(destination.has_value());
    packet::TCP tcp;
    tcp.set_source_port(source_port);
    tcp.set_destination_port(destination_port);
    tcp.set_sequence_number(0x22000000U);
    tcp.set_acknowledgment_number(acknowledgment_number);
    tcp.set_flags(flags);
    tcp.set_window(64240U);
    tcp.set_options({
        {packet::TcpOptionKind::Mss, 1460U, 0U, 0U},
        {packet::TcpOptionKind::SackPermitted, 0U, 0U, 0U},
        {packet::TcpOptionKind::Timestamp, 1U, 1U, 0U},
        {packet::TcpOptionKind::Nop, 0U, 0U, 0U},
        {packet::TcpOptionKind::WindowScale, 7U, 0U, 0U}});
    packet::IPv4 ip;
    ip.set_source_address(source_address);
    ip.set_destination_address(*destination);
    ip.set_protocol(6U);
    ip.set_flags_fragment_offset(0x4000U);
    ip.set_ttl(ttl);
    ip.set_total_length(static_cast<std::uint16_t>(ip.serialized_size() + tcp.serialized_size()));
    std::vector<std::uint8_t> bytes(ip.serialized_size() + tcp.serialized_size());
    assert(ip.serialize(std::span<std::uint8_t>{bytes}.first(ip.serialized_size())) == core::StatusCode::Ok);
    assert(tcp.serialize_with_checksum(
               std::span<std::uint8_t>{bytes}.subspan(ip.serialized_size()), source_address, *destination) ==
           core::StatusCode::Ok);
    return bytes;
}

skan::osdetect::OSProbeResponse response_for(
    const skan::osdetect::OSProbeSubmission &submission,
    std::vector<std::uint8_t> bytes,
    std::string source = {})
{
    skan::osdetect::OSProbeResponse response;
    response.id = submission.id;
    response.source_address = source.empty() ? submission.target : std::move(source);
    response.destination_address = submission.source_address;
    response.bytes = std::move(bytes);
    response.source_ip = submission.target_ip;
    response.destination_ip = submission.source_ip;
    response.ip_ttl = 64U;
    response.received_at = skan::osdetect::OSProbeClock::now();
    return response;
}

} // namespace

int main()
{
    using namespace skan;
    const core::Host host{"192.0.2.10", std::nullopt, true};
    const auto destination = discovery::parse_ipv4_address(host.address);
    assert(destination.has_value());

    const auto syn_probe = osdetect::make_os_probe(osdetect::OSProbeType::TcpSynStandard);
    assert(syn_probe != nullptr);
    osdetect::OSProbeSubmission syn_submission;
    assert(syn_probe->build(7U, host, osdetect::OSProbeConfig{}, syn_submission) == core::StatusCode::Ok);
    const auto syn_ip = packet::IPv4::parse(syn_submission.bytes);
    assert(syn_ip.has_value());
    assert(syn_ip->protocol() == 6U);
    const auto syn_tcp = packet::TCP::parse(
        std::span<const std::uint8_t>{syn_submission.bytes}.subspan(static_cast<std::size_t>(syn_ip->ihl()) * 4U));
    assert(syn_tcp.has_value());
    assert(packet::has_flag(syn_tcp->flags(), packet::TcpFlag::Syn));
    assert(!packet::has_flag(syn_tcp->flags(), packet::TcpFlag::Ack));

    const auto matching_bytes = tcp_response(
        syn_submission,
        *destination,
        syn_submission.destination_port,
        syn_submission.source_port,
        static_cast<std::uint16_t>(packet::TcpFlag::Syn) | static_cast<std::uint16_t>(packet::TcpFlag::Ack),
        syn_submission.sequence_number + 1U);
    const osdetect::OSProbeAssessment matching = syn_probe->assess(
        response_for(syn_submission, matching_bytes), syn_submission);
    assert(matching.disposition == osdetect::OSProbeDisposition::Matching);
    assert(matching.tcp_observation.has_value());
    assert(matching.tcp_observation->ttl.value == 64U);

    auto unrelated_response = response_for(syn_submission, matching_bytes, "192.0.2.11");
    const osdetect::OSProbeAssessment unrelated = syn_probe->assess(unrelated_response, syn_submission);
    assert(unrelated.disposition == osdetect::OSProbeDisposition::Unrelated);

    unrelated_response = response_for(syn_submission, tcp_response(
        syn_submission,
        *destination,
        static_cast<std::uint16_t>(syn_submission.destination_port + 1U),
        syn_submission.source_port,
        static_cast<std::uint16_t>(packet::TcpFlag::Syn) | static_cast<std::uint16_t>(packet::TcpFlag::Ack),
        syn_submission.sequence_number + 1U));
    assert(syn_probe->assess(unrelated_response, syn_submission).disposition ==
           osdetect::OSProbeDisposition::Unrelated);

    unrelated_response = response_for(syn_submission, tcp_response(
        syn_submission,
        *destination,
        syn_submission.destination_port,
        syn_submission.source_port,
        static_cast<std::uint16_t>(packet::TcpFlag::Syn) | static_cast<std::uint16_t>(packet::TcpFlag::Ack),
        syn_submission.sequence_number + 2U));
    assert(syn_probe->assess(unrelated_response, syn_submission).disposition ==
           osdetect::OSProbeDisposition::Unrelated);

    unrelated_response = response_for(syn_submission, {0x45U, 0x00U});
    const osdetect::OSProbeAssessment malformed = syn_probe->assess(unrelated_response, syn_submission);
    assert(malformed.disposition == osdetect::OSProbeDisposition::Malformed);
    assert(malformed.status == core::StatusCode::ParseError);

    const std::vector<std::pair<osdetect::OSProbeType, std::uint16_t>> tcp_probe_flags{
        {osdetect::OSProbeType::TcpAck, static_cast<std::uint16_t>(packet::TcpFlag::Ack)},
        {osdetect::OSProbeType::TcpFin, static_cast<std::uint16_t>(packet::TcpFlag::Fin)},
        {osdetect::OSProbeType::TcpNull, 0U},
        {osdetect::OSProbeType::TcpXmas, static_cast<std::uint16_t>(packet::TcpFlag::Fin) |
                                             static_cast<std::uint16_t>(packet::TcpFlag::Psh) |
                                             static_cast<std::uint16_t>(packet::TcpFlag::Urg)}};
    for (const auto &[type, expected_flags] : tcp_probe_flags) {
        const auto probe = osdetect::make_os_probe(type);
        assert(probe != nullptr);
        osdetect::OSProbeSubmission submission;
        assert(probe->build(20U + static_cast<osdetect::OSProbeId>(type), host, osdetect::OSProbeConfig{}, submission) ==
               core::StatusCode::Ok);
        const auto ip = packet::IPv4::parse(submission.bytes);
        assert(ip.has_value());
        const auto tcp = packet::TCP::parse(
            std::span<const std::uint8_t>{submission.bytes}.subspan(static_cast<std::size_t>(ip->ihl()) * 4U));
        assert(tcp.has_value());
        assert(tcp->flags() == expected_flags);
        const auto rst = tcp_response(
            submission,
            *destination,
            submission.destination_port,
            submission.source_port,
            static_cast<std::uint16_t>(packet::TcpFlag::Rst),
            0U);
        const auto assessment = probe->assess(response_for(submission, rst), submission);
        assert(assessment.disposition == osdetect::OSProbeDisposition::Matching);
        assert(assessment.response_behavior == osdetect::ResponseBehavior::Rst);
        assert(assessment.tcp_observation.has_value());
    }

    const auto icmp_probe = osdetect::make_os_probe(osdetect::OSProbeType::IcmpEcho);
    assert(icmp_probe != nullptr);
    osdetect::OSProbeSubmission icmp_submission;
    assert(icmp_probe->build(9U, host, osdetect::OSProbeConfig{}, icmp_submission) == core::StatusCode::Ok);
    const auto icmp = packet::ICMP::parse(icmp_submission.bytes);
    assert(icmp.has_value());
    assert(icmp->identifier() == icmp_submission.correlation_identifier);
    assert(icmp->sequence() == icmp_submission.correlation_sequence);
    packet::ICMP icmp_reply(packet::IcmpType::EchoReply);
    icmp_reply.set_identifier(icmp_submission.correlation_identifier);
    icmp_reply.set_sequence(icmp_submission.correlation_sequence);
    icmp_reply.set_payload({0x53U, 0x4BU});
    auto icmp_response = response_for(icmp_submission, icmp_reply.serialize());
    icmp_response.ip_ttl = 55U;
    const auto icmp_assessment = icmp_probe->assess(icmp_response, icmp_submission);
    assert(icmp_assessment.disposition == osdetect::OSProbeDisposition::Matching);
    assert(icmp_assessment.response_behavior == osdetect::ResponseBehavior::EchoReply);
    assert(icmp_assessment.icmp_observation.has_value());

    core::Host ipv6_host;
    ipv6_host.address = "::1";
    ipv6_host.is_up = true;
    ipv6_host.ip_address = *core::parse_ip_address("::1");
    osdetect::OSProbeConfig ipv6_config;
    ipv6_config.source_address = "::1";
    const auto ipv6_syn_probe = osdetect::make_os_probe(osdetect::OSProbeType::TcpSynStandard);
    assert(ipv6_syn_probe != nullptr);
    osdetect::OSProbeSubmission ipv6_syn_submission;
    assert(ipv6_syn_probe->build(31U, ipv6_host, ipv6_config, ipv6_syn_submission) == core::StatusCode::Ok);
    assert(ipv6_syn_submission.target_ip.is_ipv6());
    const auto ipv6_header = packet::IPv6::parse(ipv6_syn_submission.bytes);
    assert(ipv6_header.has_value());
    assert(ipv6_header->next_header() == 6U);
    const auto ipv6_tcp = packet::TCP::parse(
        std::span<const std::uint8_t>{ipv6_syn_submission.bytes}.subspan(packet::IPv6::kHeaderSize));
    assert(ipv6_tcp.has_value());
    packet::TCP ipv6_reply;
    ipv6_reply.set_source_port(ipv6_syn_submission.destination_port);
    ipv6_reply.set_destination_port(ipv6_syn_submission.source_port);
    ipv6_reply.set_sequence_number(0x33000000U);
    ipv6_reply.set_acknowledgment_number(ipv6_syn_submission.sequence_number + 1U);
    ipv6_reply.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Syn) |
                         static_cast<std::uint16_t>(packet::TcpFlag::Ack));
    ipv6_reply.set_window(60000U);
    const auto ipv6_tcp_assessment = ipv6_syn_probe->assess(
        response_for(ipv6_syn_submission, ipv6_reply.serialize()), ipv6_syn_submission);
    assert(ipv6_tcp_assessment.disposition == osdetect::OSProbeDisposition::Matching);
    assert(ipv6_tcp_assessment.tcp_observation.has_value());
    assert(ipv6_tcp_assessment.tcp_observation->source_address == "::1");

    const auto ipv6_icmp_probe = osdetect::make_os_probe(osdetect::OSProbeType::IcmpEcho);
    assert(ipv6_icmp_probe != nullptr);
    osdetect::OSProbeSubmission ipv6_icmp_submission;
    assert(ipv6_icmp_probe->build(32U, ipv6_host, ipv6_config, ipv6_icmp_submission) == core::StatusCode::Ok);
    const auto ipv6_icmp = packet::ICMPv6::parse(ipv6_icmp_submission.bytes);
    assert(ipv6_icmp.has_value());
    packet::ICMPv6 ipv6_icmp_reply(packet::Icmpv6Type::EchoReply);
    ipv6_icmp_reply.set_identifier(ipv6_icmp_submission.correlation_identifier);
    ipv6_icmp_reply.set_sequence(ipv6_icmp_submission.correlation_sequence);
    ipv6_icmp_reply.set_payload({0x53U, 0x4BU});
    auto ipv6_icmp_response = response_for(ipv6_icmp_submission, ipv6_icmp_reply.serialize());
    const auto ipv6_icmp_assessment = ipv6_icmp_probe->assess(ipv6_icmp_response, ipv6_icmp_submission);
    assert(ipv6_icmp_assessment.disposition == osdetect::OSProbeDisposition::Matching);
    assert(ipv6_icmp_assessment.icmp_observation.has_value());

    osdetect::RecordingOSProbeTransport transport;
    assert(transport.supports(osdetect::OSProbeType::TcpSynStandard));
    assert(transport.supports(osdetect::OSProbeType::UdpFingerprint));
    const auto udp_probe = osdetect::make_os_probe(osdetect::OSProbeType::UdpFingerprint);
    assert(udp_probe != nullptr);
    osdetect::OSProbeSubmission udp_submission;
    osdetect::OSProbeConfig udp_config;
    assert(udp_probe->build(11U, host, udp_config, udp_submission) == core::StatusCode::Ok);
    assert(packet::UDP::parse(udp_submission.bytes).has_value());

    packet::UDP udp_response;
    udp_response.set_source_port(udp_submission.destination_port);
    udp_response.set_destination_port(udp_submission.source_port);
    udp_response.set_payload({0x01U, 0x02U});
    const auto udp_assessment = udp_probe->assess(
        response_for(udp_submission, udp_response.serialize()), udp_submission);
    assert(udp_assessment.disposition == osdetect::OSProbeDisposition::Matching);
    assert(udp_assessment.response_behavior == osdetect::ResponseBehavior::UdpResponse);
    assert(udp_assessment.udp_observation.has_value());
    assert(udp_assessment.udp_observation->payload_length.value == 2U);

    const auto source = discovery::parse_ipv4_address(udp_submission.source_address);
    assert(source.has_value());
    packet::IPv4 quoted_ip;
    quoted_ip.set_source_address(*source);
    quoted_ip.set_destination_address(*destination);
    quoted_ip.set_protocol(17U);
    quoted_ip.set_total_length(static_cast<std::uint16_t>(quoted_ip.serialized_size() + udp_submission.bytes.size()));
    std::vector<std::uint8_t> quoted(quoted_ip.serialized_size() + udp_submission.bytes.size());
    assert(quoted_ip.serialize(std::span<std::uint8_t>{quoted}.first(quoted_ip.serialized_size())) == core::StatusCode::Ok);
    std::copy(udp_submission.bytes.begin(), udp_submission.bytes.end(), quoted.begin() +
              static_cast<std::ptrdiff_t>(quoted_ip.serialized_size()));
    packet::ICMP destination_unreachable(packet::IcmpType::DestinationUnreachable);
    destination_unreachable.set_code(3U);
    destination_unreachable.set_payload(std::move(quoted));
    auto icmp_error_response = response_for(udp_submission, destination_unreachable.serialize());
    icmp_error_response.kind = osdetect::OSProbeResponseKind::IcmpError;
    const auto icmp_error_assessment = udp_probe->assess(icmp_error_response, udp_submission);
    assert(icmp_error_assessment.disposition == osdetect::OSProbeDisposition::Matching);
    assert(icmp_error_assessment.response_behavior == osdetect::ResponseBehavior::PortUnreachable);

    auto malformed_error = icmp_error_response;
    malformed_error.bytes = {0x03U, 0x00U};
    const auto malformed_error_assessment = udp_probe->assess(malformed_error, udp_submission);
    assert(malformed_error_assessment.disposition == osdetect::OSProbeDisposition::Malformed);
    assert(malformed_error_assessment.status == core::StatusCode::ParseError);

    std::size_t callbacks = 0U;
    assert(transport.submit(syn_submission, [&callbacks](const osdetect::OSProbeResponse &) { ++callbacks; }) ==
           core::StatusCode::Ok);
    transport.deliver(response_for(syn_submission, matching_bytes));
    assert(callbacks == 1U);
    assert(transport.cancel(syn_submission.id) == core::StatusCode::Ok);
    transport.deliver(response_for(syn_submission, matching_bytes));
    assert(callbacks == 1U);
    return 0;
}
