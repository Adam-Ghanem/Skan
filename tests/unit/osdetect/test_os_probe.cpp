#include <cassert>
#include <chrono>
#include <optional>
#include <vector>

#include "discovery/discovery_types.hpp"
#include "packet/icmp.hpp"
#include "osdetect/os_probe.hpp"
#include "packet/ipv4.hpp"
#include "packet/tcp.hpp"

namespace {

std::vector<std::uint8_t> tcp_response(
    const skan::osdetect::OSProbeSubmission &submission,
    std::uint32_t source_address,
    std::uint8_t ttl = 64U)
{
    using namespace skan;
    const auto destination = discovery::parse_ipv4_address(submission.source_address);
    assert(destination.has_value());
    packet::TCP tcp;
    tcp.set_source_port(submission.destination_port);
    tcp.set_destination_port(submission.source_port);
    tcp.set_sequence_number(0x22000000U);
    tcp.set_acknowledgment_number(submission.sequence_number + 1U);
    tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Syn) |
                  static_cast<std::uint16_t>(packet::TcpFlag::Ack));
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

} // namespace

int main()
{
    using namespace skan;
    const core::Host host{"192.0.2.10", std::nullopt, true};
    const auto probe = osdetect::make_os_probe(osdetect::OSProbeType::TcpSynStandard);
    assert(probe != nullptr);
    osdetect::OSProbeSubmission submission;
    assert(probe->build(7U, host, osdetect::OSProbeConfig{}, submission) == core::StatusCode::Ok);
    assert(!submission.bytes.empty());
    const auto ip = packet::IPv4::parse(submission.bytes);
    assert(ip.has_value());
    assert(ip->protocol() == 6U);

    const auto destination = discovery::parse_ipv4_address(host.address);
    assert(destination.has_value());
    const auto matching_bytes = tcp_response(submission, *destination);
    osdetect::OSProbeResponse matching_response;
    matching_response.id = submission.id;
    matching_response.source_address = host.address;
    matching_response.destination_address = submission.source_address;
    matching_response.bytes = matching_bytes;
    matching_response.received_at = osdetect::OSProbeClock::now();
    const osdetect::OSProbeAssessment matching = probe->assess(matching_response, submission);
    assert(matching.disposition == osdetect::OSProbeDisposition::Matching);
    assert(matching.tcp_observation.has_value());
    assert(matching.tcp_observation->ttl.value == 64U);

    matching_response.source_address = "192.0.2.11";
    const osdetect::OSProbeAssessment unrelated = probe->assess(matching_response, submission);
    assert(unrelated.disposition == osdetect::OSProbeDisposition::Unrelated);

    matching_response.source_address = host.address;
    matching_response.bytes = {0x45U, 0x00U};
    const osdetect::OSProbeAssessment malformed = probe->assess(matching_response, submission);
    assert(malformed.disposition == osdetect::OSProbeDisposition::Malformed);
    assert(malformed.status == core::StatusCode::ParseError);

    const auto icmp_probe = osdetect::make_os_probe(osdetect::OSProbeType::IcmpEcho);
    assert(icmp_probe != nullptr);
    osdetect::OSProbeSubmission icmp_submission;
    assert(icmp_probe->build(9U, host, osdetect::OSProbeConfig{}, icmp_submission) == core::StatusCode::Ok);
    assert(icmp_submission.bytes.size() >= packet::ICMP::kHeaderSize);
    const auto icmp = packet::ICMP::parse(icmp_submission.bytes);
    assert(icmp.has_value());
    assert(icmp->identifier() == icmp_submission.correlation_identifier);

    osdetect::RecordingOSProbeTransport transport;
    assert(transport.supports(osdetect::OSProbeType::TcpSynStandard));
    assert(!transport.supports(osdetect::OSProbeType::UdpPortUnreachable));
    std::size_t callbacks = 0U;
    assert(transport.submit(submission, [&callbacks](const osdetect::OSProbeResponse &) { ++callbacks; }) ==
           core::StatusCode::Ok);
    transport.deliver(matching_response);
    assert(callbacks == 1U);
    assert(transport.cancel(submission.id) == core::StatusCode::Ok);
    transport.deliver(matching_response);
    assert(callbacks == 1U);
    return 0;
}
