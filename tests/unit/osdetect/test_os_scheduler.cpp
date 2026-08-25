#include <cassert>
#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "db/os_db.hpp"
#include "discovery/discovery_types.hpp"
#include "osdetect/os_scheduler.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

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
    if (submission.type == osdetect::OSProbeType::UdpFingerprint ||
        submission.type == osdetect::OSProbeType::UdpPortUnreachable) {
        const auto request = packet::UDP::parse(submission.bytes);
        assert(request.has_value());
        packet::UDP reply;
        reply.set_source_port(request->destination_port());
        reply.set_destination_port(request->source_port());
        reply.set_payload({0x01U, 0x02U, 0x03U});
        return reply.serialize();
    }
    const auto source = discovery::parse_ipv4_address(submission.target);
    const auto destination = discovery::parse_ipv4_address(submission.source_address);
    assert(source.has_value() && destination.has_value());
    packet::TCP tcp;
    tcp.set_source_port(submission.destination_port);
    tcp.set_destination_port(submission.source_port);
    tcp.set_sequence_number(0x33000000U);
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

void deliver_all_matching(
    skan::osdetect::OSScheduler &scheduler,
    skan::osdetect::RecordingOSProbeTransport &transport)
{
    using namespace skan;
    std::size_t index = 0U;
    while (!scheduler.complete()) {
        assert(index < 20000U);
        const osdetect::OSProbeSubmission submission = transport.submissions()[index++];
        osdetect::OSProbeResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.destination_address = submission.source_address;
        response.bytes = response_for(submission);
        response.received_at = osdetect::OSProbeClock::now();
        transport.deliver(std::move(response));
    }
}

} // namespace

int main()
{
    using namespace skan;
    const db::OSFingerprintDatabase database = db::OSFingerprintDatabase::built_in();
    const core::Target target{
        "two-hosts",
        {core::Host{"192.0.2.10", std::nullopt, true}, core::Host{"192.0.2.11", std::nullopt, true}}};
    const std::vector<portscan::PortResult> ports{
        {"192.0.2.10", {8080U, portscan::Protocol::Tcp}, portscan::PortState::Open,
         portscan::ScanProbeType::TcpConnect, portscan::ScanReason::ImmediateSuccess, std::nullopt, {}, 0U, std::nullopt},
        {"192.0.2.11", {8081U, portscan::Protocol::Tcp}, portscan::PortState::Open,
         portscan::ScanProbeType::TcpConnect, portscan::ScanReason::ImmediateSuccess, std::nullopt, {}, 0U, std::nullopt}};

    io::IOEngine engine;
    osdetect::RecordingOSProbeTransport transport;
    osdetect::OSSchedulerConfig config;
    config.max_outstanding = 2U;
    config.probe_port = 8080U;
    config.timeout = std::chrono::milliseconds{20};
    osdetect::OSScheduler scheduler(engine, transport, database, config);
    assert(scheduler.submit(target, ports) == core::StatusCode::Ok);
    assert(scheduler.pending_count() == 2U);
    assert(transport.submissions().size() == 2U);
    deliver_all_matching(scheduler, transport);
    assert(scheduler.complete());
    assert(scheduler.result().has_value());
    assert(scheduler.result()->state == osdetect::OSDetectionState::Complete);
    assert(scheduler.result()->responses_received == 24U);
    assert(scheduler.result()->probes_unsupported == 0U);
    assert(scheduler.result()->matches.front().fingerprint_name == "SkanLinuxGeneric");
    assert(scheduler.result()->confidence == 1.0);

    io::IOEngine timeout_engine;
    osdetect::RecordingOSProbeTransport timeout_transport;
    config.max_outstanding = 1U;
    config.timeout = std::chrono::milliseconds{1};
    osdetect::OSScheduler timeout_scheduler(timeout_engine, timeout_transport, database, config);
    assert(timeout_scheduler.submit(
               core::Target{"one-host", {core::Host{"192.0.2.12", std::nullopt, true}}}, ports) ==
           core::StatusCode::Ok);
    assert(timeout_scheduler.pending_count() == 1U);
    assert(timeout_scheduler.run() == core::StatusCode::Ok);
    assert(timeout_scheduler.complete());
    assert(timeout_scheduler.result().has_value());
    assert(timeout_scheduler.result()->state == osdetect::OSDetectionState::Partial);
    assert(timeout_scheduler.result()->probes_timed_out == 12U);
    assert(timeout_scheduler.result()->probes_unsupported == 0U);

    io::IOEngine cancelled_engine;
    osdetect::RecordingOSProbeTransport cancelled_transport;
    osdetect::OSScheduler cancelled_scheduler(cancelled_engine, cancelled_transport, database, config);
    assert(cancelled_scheduler.submit(
               core::Target{"cancelled", {core::Host{"192.0.2.13", std::nullopt, true}}}, ports) ==
           core::StatusCode::Ok);
    assert(cancelled_scheduler.pending_count() == 1U);
    cancelled_scheduler.stop();
    assert(cancelled_scheduler.result().has_value());
    assert(cancelled_scheduler.result()->state == osdetect::OSDetectionState::Partial);
    assert(cancelled_scheduler.pending_count() == 0U);

    std::vector<core::Host> stress_hosts;
    stress_hosts.reserve(1000U);
    for (std::size_t index = 0U; index < 1000U; ++index) {
        const std::string address = "198.18." + std::to_string(index / 256U) + "." +
                                    std::to_string(index % 256U);
        stress_hosts.push_back(core::Host{address, std::nullopt, true});
    }
    io::IOEngine stress_engine;
    osdetect::RecordingOSProbeTransport stress_transport;
    osdetect::OSSchedulerConfig stress_config = config;
    stress_config.max_outstanding = 32U;
    stress_config.timeout = std::chrono::milliseconds{50};
    osdetect::OSScheduler stress_scheduler(
        stress_engine, stress_transport, database, stress_config);
    assert(stress_scheduler.submit(core::Target{"one-thousand-hosts", std::move(stress_hosts)}, {}) ==
           core::StatusCode::Ok);
    deliver_all_matching(stress_scheduler, stress_transport);
    assert(stress_scheduler.complete());
    assert(stress_scheduler.result().has_value());
    assert(stress_scheduler.result()->state == osdetect::OSDetectionState::Complete);
    assert(stress_scheduler.result()->responses_received == 12000U);
    return 0;
}
