#include <cassert>
#include <optional>
#include <vector>

#include "db/os_db.hpp"
#include "discovery/discovery_types.hpp"
#include "osdetect/os_detector.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/tcp.hpp"

namespace {

std::vector<std::uint8_t> response_for(const skan::osdetect::OSProbeSubmission &submission)
{
    using namespace skan;
    if (submission.type == osdetect::OSProbeType::IcmpEcho) {
        const auto request = packet::ICMP::parse(submission.bytes);
        assert(request.has_value());
        packet::ICMP reply(packet::IcmpType::EchoReply);
        reply.set_identifier(request->identifier());
        reply.set_sequence(request->sequence());
        reply.set_payload(request->payload());
        return reply.serialize();
    }
    const auto source = discovery::parse_ipv4_address(submission.target);
    const auto destination = discovery::parse_ipv4_address(submission.source_address);
    assert(source.has_value() && destination.has_value());
    packet::TCP tcp;
    tcp.set_source_port(submission.destination_port);
    tcp.set_destination_port(submission.source_port);
    tcp.set_sequence_number(0x44000000U);
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
    ip.set_source_address(*source);
    ip.set_destination_address(*destination);
    ip.set_protocol(6U);
    ip.set_flags_fragment_offset(0x4000U);
    ip.set_total_length(static_cast<std::uint16_t>(ip.serialized_size() + tcp.serialized_size()));
    std::vector<std::uint8_t> bytes(ip.serialized_size() + tcp.serialized_size());
    assert(ip.serialize(std::span<std::uint8_t>{bytes}.first(ip.serialized_size())) == core::StatusCode::Ok);
    assert(tcp.serialize_with_checksum(
               std::span<std::uint8_t>{bytes}.subspan(ip.serialized_size()), *source, *destination) ==
           core::StatusCode::Ok);
    return bytes;
}

} // namespace

int main()
{
    using namespace skan;
    io::IOEngine engine;
    osdetect::RecordingOSProbeTransport transport;
    osdetect::OSSchedulerConfig config;
    config.max_outstanding = 2U;
    config.timeout = std::chrono::milliseconds{20};
    osdetect::OSDetector detector(engine, transport, config, db::OSFingerprintDatabase::built_in());
    const core::Target target{"192.0.2.20", {core::Host{"192.0.2.20", std::nullopt, true}}};
    const std::vector<portscan::PortResult> ports{
        {"192.0.2.20", {443U, portscan::Protocol::Tcp}, portscan::PortState::Open,
         portscan::ScanProbeType::TcpConnect, portscan::ScanReason::ImmediateSuccess, std::nullopt, {}}};
    assert(detector.submit(target, ports, {}) == core::StatusCode::Ok);

    std::size_t index = 0U;
    while (!detector.complete()) {
        assert(index < 16U);
        const osdetect::OSProbeSubmission submission = transport.submissions()[index++];
        osdetect::OSProbeResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.destination_address = submission.source_address;
        response.bytes = response_for(submission);
        transport.deliver(std::move(response));
    }
    assert(detector.result().has_value());
    assert(detector.result()->state == osdetect::OSDetectionState::Complete);
    assert(detector.result()->confidence > 0.0);
    assert(detector.result()->matches.front().fingerprint_name == "SkanLinuxGeneric");
    return 0;
}
