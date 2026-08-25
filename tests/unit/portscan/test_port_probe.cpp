#include <cassert>
#include <cerrno>
#include <cstdint>
#include <vector>

#include "packet/tcp.hpp"
#include "portscan/port_probe.hpp"
#include "portscan/tcp_connect.hpp"
#include "portscan/tcp_syn.hpp"

namespace {

skan::portscan::PortSubmission make_syn_submission()
{
    skan::portscan::TcpSynProbe probe;
    skan::portscan::PortSubmission submission;
    const skan::core::Host host{"127.0.0.1", std::nullopt, true};
    const skan::portscan::Port port{443U, skan::portscan::Protocol::Tcp};
    const skan::portscan::PortScanConfig config{skan::portscan::ScanProbeType::TcpSyn,
                                                 std::chrono::milliseconds{100},
                                                 2U};
    assert(probe.build(7U, host, port, config, submission) == skan::core::StatusCode::Ok);
    return submission;
}

std::vector<std::uint8_t> serialize_tcp(const skan::packet::TCP &tcp)
{
    std::vector<std::uint8_t> bytes(tcp.serialized_size());
    assert(tcp.serialize(bytes) == skan::core::StatusCode::Ok);
    return bytes;
}

} // namespace

int main()
{
    using namespace skan::portscan;

    TcpConnectProbe connect_probe;
    PortSubmission connect_submission;
    const skan::core::Host host{"127.0.0.1", std::nullopt, true};
    const Port port{80U, Protocol::Tcp};
    const PortScanConfig connect_config{};
    assert(connect_probe.build(1U, host, port, connect_config, connect_submission) ==
           skan::core::StatusCode::Ok);

    PortState state = PortState::Unknown;
    ScanReason reason = ScanReason::InternalError;
    PortResponse connected{1U, "127.0.0.1", PortResponseKind::Connected, 0, {}, PortScanClock::now()};
    assert(connect_probe.assess(connected, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Open);
    assert(reason == ScanReason::ImmediateSuccess);

    PortResponse refused{1U, "127.0.0.1", PortResponseKind::ConnectionRefused, ECONNREFUSED, {},
                         PortScanClock::now()};
    assert(connect_probe.assess(refused, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Closed);
    assert(reason == ScanReason::ConnectionRefused);
    PortResponse wrong_id{2U, "127.0.0.1", PortResponseKind::Connected, 0, {}, PortScanClock::now()};
    assert(connect_probe.assess(wrong_id, connect_submission, state, reason) == skan::core::StatusCode::NotFound);

    TcpSynProbe syn_probe;
    PortSubmission syn_submission = make_syn_submission();
    const auto parsed_request = skan::packet::TCP::parse(syn_submission.packet);
    assert(parsed_request.has_value());
    assert(parsed_request->source_port() == syn_submission.source_port);
    assert(parsed_request->destination_port() == syn_submission.port.number);
    assert(skan::packet::has_flag(parsed_request->flags(), skan::packet::TcpFlag::Syn));
    assert(!skan::packet::has_flag(parsed_request->flags(), skan::packet::TcpFlag::Ack));

    skan::packet::TCP syn_ack;
    syn_ack.set_source_port(syn_submission.port.number);
    syn_ack.set_destination_port(syn_submission.source_port);
    syn_ack.set_sequence_number(123U);
    syn_ack.set_acknowledgment_number(syn_submission.sequence_number + 1U);
    syn_ack.set_flags(skan::packet::TcpFlag::Syn | skan::packet::TcpFlag::Ack);
    syn_ack.set_window(4096U);
    PortResponse syn_ack_response{7U, "127.0.0.1", PortResponseKind::Packet, 0,
                                  serialize_tcp(syn_ack), PortScanClock::now()};
    assert(syn_probe.assess(syn_ack_response, syn_submission, state, reason) ==
           skan::core::StatusCode::Ok);
    assert(state == PortState::Open);
    assert(reason == ScanReason::SynAck);

    skan::packet::TCP rst;
    rst.set_source_port(syn_submission.port.number);
    rst.set_destination_port(syn_submission.source_port);
    rst.set_sequence_number(456U);
    rst.set_acknowledgment_number(syn_submission.sequence_number + 1U);
    rst.set_flags(skan::packet::TcpFlag::Rst | skan::packet::TcpFlag::Ack);
    rst.set_window(0U);
    PortResponse rst_response{7U, "127.0.0.1", PortResponseKind::Packet, 0,
                              serialize_tcp(rst), PortScanClock::now()};
    assert(syn_probe.assess(rst_response, syn_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Closed);
    assert(reason == ScanReason::Rst);

    PortResponse malformed{7U, "127.0.0.1", PortResponseKind::Packet, 0, {1U}, PortScanClock::now()};
    assert(syn_probe.assess(malformed, syn_submission, state, reason) == skan::core::StatusCode::ParseError);
    PortResponse unrelated{7U, "127.0.0.2", PortResponseKind::Packet, 0,
                           serialize_tcp(syn_ack), PortScanClock::now()};
    assert(syn_probe.assess(unrelated, syn_submission, state, reason) == skan::core::StatusCode::NotFound);
    assert(!tcp_syn_network_capability_available());

    const auto scoped_ip = skan::core::parse_ip_address("fe80::1%lo");
    assert(scoped_ip.has_value());
    PortSubmission ipv6_syn_submission;
    const skan::core::Host ipv6_host{"fe80::1%lo", std::nullopt, true, *scoped_ip};
    assert(syn_probe.build(8U, ipv6_host, port, PortScanConfig{}, ipv6_syn_submission) ==
           skan::core::StatusCode::Ok);
    assert(ipv6_syn_submission.target_ip == *scoped_ip);
    const auto parsed_ipv6_request = skan::packet::TCP::parse(ipv6_syn_submission.packet);
    assert(parsed_ipv6_request.has_value());
    skan::packet::TCP ipv6_syn_ack;
    ipv6_syn_ack.set_source_port(port.number);
    ipv6_syn_ack.set_destination_port(ipv6_syn_submission.source_port);
    ipv6_syn_ack.set_sequence_number(123U);
    ipv6_syn_ack.set_acknowledgment_number(ipv6_syn_submission.sequence_number + 1U);
    ipv6_syn_ack.set_flags(skan::packet::TcpFlag::Syn | skan::packet::TcpFlag::Ack);
    ipv6_syn_ack.set_window(4096U);
    PortResponse ipv6_syn_ack_response{8U, "fe80::1%lo", PortResponseKind::Packet, 0,
                                       serialize_tcp(ipv6_syn_ack), PortScanClock::now(), *scoped_ip};
    assert(syn_probe.assess(ipv6_syn_ack_response, ipv6_syn_submission, state, reason) ==
           skan::core::StatusCode::Ok);
    assert(state == PortState::Open);
    assert(reason == ScanReason::SynAck);

    RecordingPortScanTransport recording;
    bool delivered = false;
    assert(recording.submit(connect_submission, [&delivered](const PortResponse &) { delivered = true; }) ==
           skan::core::StatusCode::Ok);
    assert(recording.submissions().size() == 1U);
    recording.deliver(connected);
    assert(delivered);
    recording.deliver(connected);
    return 0;
}
