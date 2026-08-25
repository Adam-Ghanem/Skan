#include <cassert>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#include "packet/udp.hpp"
#include "portscan/udp_scan.hpp"

int main()
{
    using namespace skan;
    using namespace portscan;

    const PortSelection ports = parse_udp_ports("161,53,69-70,53");
    assert(ports.status == core::StatusCode::Ok);
    assert(ports.ports.size() == 4U);
    assert((ports.ports[0] == Port{53U, Protocol::Udp}));
    assert((ports.ports[1] == Port{69U, Protocol::Udp}));
    assert((ports.ports[2] == Port{70U, Protocol::Udp}));
    assert((ports.ports[3] == Port{161U, Protocol::Udp}));
    assert(parse_udp_ports("0").status == core::StatusCode::InvalidArgument);
    assert(parse_udp_ports("70000").status == core::StatusCode::InvalidArgument);
    assert(parse_udp_ports("2-").status == core::StatusCode::InvalidArgument);
    assert(default_udp_ports().size() == 10U);
    assert(default_udp_ports().front().number == 53U);
    assert(std::string{port_state_name(PortState::OpenOrFiltered)} == "OPEN_OR_FILTERED");
    assert(std::string{scan_reason_name(ScanReason::IcmpPortUnreachable)} == "ICMP_PORT_UNREACHABLE");

    core::StatusCode database_status = core::StatusCode::InternalError;
    const UDPProbeDatabase database = UDPProbeDatabase::built_in();
    assert(database.definitions().size() == 7U);
    assert(database.for_port(53U)->name == "DNS");
    assert(database.for_port(9999U)->name == "DEFAULT");
    assert(database.default_probe().destination_port == 0U);
    assert(UDPProbeDatabase::parse("probe A 53 dns 10 00\nprobe A 54 x 10 00\n", database_status).definitions().empty());
    assert(database_status == core::StatusCode::ParseError);
    assert(UDPProbeDatabase::parse("probe A 53 dns 10 0g\nprobe DEFAULT 0 x 10 00\n", database_status).definitions().empty());
    assert(database_status == core::StatusCode::ParseError);
    assert(UDPProbeDatabase::parse("probe A 53 dns 10 00\n", database_status).definitions().empty());
    assert(database_status == core::StatusCode::ParseError);
    assert(UDPProbeDatabase::parse("probe A 53 dns 10 00\nprobe DEFAULT 0 x 10 00\nextra\n", database_status).definitions().empty());
    assert(database_status == core::StatusCode::ParseError);

    io::IOEngine engine;
    assert(engine.initialization_status() == core::StatusCode::Ok);
    RecordingUDPTransport transport;
    PortScanConfig config;
    config.method = ScanProbeType::Udp;
    config.timeout = std::chrono::milliseconds{5};
    config.max_outstanding = 2U;
    config.retries = 1U;
    UDPScheduler scheduler(engine, transport, database, config);
    const core::Target target{"192.0.2.10", {core::Host{"192.0.2.10", std::nullopt, false}}};
    const std::vector<Port> scan_ports{{53U, Protocol::Udp}, {69U, Protocol::Udp}, {161U, Protocol::Udp}};
    assert(scheduler.submit(target, scan_ports) == core::StatusCode::Ok);
    assert(scheduler.pending_count() == 2U);
    assert(transport.submissions().size() == 2U);

    UDPResponse unrelated;
    unrelated.id = 999999U;
    unrelated.kind = UDPResponseKind::Datagram;
    transport.deliver(unrelated);
    assert(scheduler.results().empty());

    packet::UDP response_packet;
    response_packet.set_source_port(53U);
    response_packet.set_destination_port(transport.submissions()[0].source_port);
    response_packet.set_payload({0x42U});
    std::vector<std::uint8_t> response_bytes(response_packet.serialized_size(), 0U);
    assert(response_packet.serialize(response_bytes) == core::StatusCode::Ok);
    UDPResponse open_response;
    open_response.id = transport.submissions()[0].id;
    open_response.source_ipv4 = 0xC000020AU;
    open_response.source_port = 53U;
    open_response.destination_port = transport.submissions()[0].source_port;
    open_response.kind = UDPResponseKind::Datagram;
    open_response.bytes = response_bytes;
    transport.deliver(open_response);
    assert(scheduler.results().size() == 1U);
    assert(scheduler.results()[0].state == PortState::Open);
    assert(scheduler.results()[0].probe_name.has_value());
    assert(scheduler.pending_count() == 2U);

    UDPResponse closed_response;
    closed_response.id = transport.submissions()[1].id;
    closed_response.source_ipv4 = 0xC000020AU;
    closed_response.source_port = 69U;
    closed_response.destination_port = transport.submissions()[1].source_port;
    closed_response.kind = UDPResponseKind::IcmpPortUnreachable;
    transport.deliver(closed_response);
    assert(scheduler.results().size() == 2U);
    assert(scheduler.results()[1].state == PortState::Closed);
    transport.deliver(closed_response);
    assert(scheduler.results().size() == 2U);

    assert(scheduler.run() == core::StatusCode::Ok);
    assert(scheduler.complete());
    assert(scheduler.results().size() == 3U);
    const PortResult *timed_out = nullptr;
    for (const PortResult &result : scheduler.results()) {
        if (result.port.number == 161U) {
            timed_out = &result;
        }
    }
    assert(timed_out != nullptr);
    assert(timed_out->state == PortState::OpenOrFiltered);
    assert(timed_out->reason == ScanReason::UdpTimeout);
    assert(timed_out->retry_count == 1U);

    RecordingUDPTransport malformed_transport;
    PortScanConfig malformed_config = config;
    malformed_config.retries = 0U;
    UDPScheduler malformed_scheduler(engine, malformed_transport, database, malformed_config);
    assert(malformed_scheduler.submit(target, {{53U, Protocol::Udp}}) == core::StatusCode::Ok);
    UDPResponse malformed;
    malformed.id = malformed_transport.submissions().front().id;
    malformed.kind = UDPResponseKind::Datagram;
    malformed.bytes = {0x00U, 0x01U};
    malformed_transport.deliver(malformed);
    assert(malformed_scheduler.results().front().state == PortState::Error);
    assert(malformed_scheduler.results().front().reason == ScanReason::MalformedResponse);

    auto drain_recording = [](RecordingUDPTransport &recording) {
        std::size_t index = 0U;
        while (index < recording.submissions().size()) {
            const UDPSubmission &submission = recording.submissions()[index++];
            packet::UDP stress_response_packet;
            stress_response_packet.set_source_port(submission.port.number);
            stress_response_packet.set_destination_port(submission.source_port);
            stress_response_packet.set_payload({0x01U});
            std::vector<std::uint8_t> bytes(stress_response_packet.serialized_size(), 0U);
            assert(stress_response_packet.serialize(bytes) == core::StatusCode::Ok);
            recording.deliver(UDPResponse{submission.id, {}, 0U, submission.port.number, submission.source_port,
                                          UDPResponseKind::Datagram, std::move(bytes), UDPScanClock::now()});
        }
    };
    std::vector<core::Host> stress_hosts;
    for (unsigned int host_index = 1U; host_index <= 100U; ++host_index) {
        stress_hosts.push_back(core::Host{"198.51.100." + std::to_string(host_index), std::nullopt, false});
    }
    core::Target stress_target{"198.51.100.0/24", stress_hosts};
    std::vector<Port> hundred_ports;
    for (unsigned int port_index = 0U; port_index < 100U; ++port_index) {
        hundred_ports.push_back(Port{static_cast<std::uint16_t>(10000U + port_index), Protocol::Udp});
    }
    RecordingUDPTransport stress_transport;
    PortScanConfig stress_config = config;
    stress_config.max_outstanding = 64U;
    stress_config.retries = 0U;
    UDPScheduler stress_scheduler(engine, stress_transport, database, stress_config);
    assert(stress_scheduler.submit(stress_target, hundred_ports) == core::StatusCode::Ok);
    drain_recording(stress_transport);
    assert(stress_scheduler.run() == core::StatusCode::Ok);
    assert(stress_scheduler.results().size() == 10000U);

    std::vector<Port> one_hundred_thousand_ports;
    one_hundred_thousand_ports.reserve(100000U);
    for (unsigned int operation = 0U; operation < 100000U; ++operation) {
        one_hundred_thousand_ports.push_back(
            Port{static_cast<std::uint16_t>(20000U + (operation % 1000U)), Protocol::Udp});
    }
    RecordingUDPTransport hundred_thousand_transport;
    UDPScheduler hundred_thousand_scheduler(engine, hundred_thousand_transport, database, stress_config);
    assert(hundred_thousand_scheduler.submit(
               core::Target{"192.0.2.20", {core::Host{"192.0.2.20", std::nullopt, false}}},
               one_hundred_thousand_ports) == core::StatusCode::Ok);
    drain_recording(hundred_thousand_transport);
    assert(hundred_thousand_scheduler.run() == core::StatusCode::Ok);
    assert(hundred_thousand_scheduler.results().size() == 100000U);
    std::cout << "udp scan tests passed\n";
    return 0;
}
