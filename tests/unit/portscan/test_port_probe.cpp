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

    PortResponse timeout{1U, "127.0.0.1", PortResponseKind::SocketError, ETIMEDOUT, {}, PortScanClock::now()};
    assert(connect_probe.assess(timeout, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Filtered);
    assert(reason == ScanReason::Timeout);

    PortResponse unreachable{1U, "127.0.0.1", PortResponseKind::SocketError, ENETUNREACH, {}, PortScanClock::now()};
    assert(connect_probe.assess(unreachable, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Unreachable);
    assert(reason == ScanReason::NetworkUnreachable);

    PortResponse host_unreachable{1U, "127.0.0.1", PortResponseKind::SocketError, EHOSTUNREACH, {}, PortScanClock::now()};
    assert(connect_probe.assess(host_unreachable, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Unreachable);

    PortResponse local_address{1U, "127.0.0.1", PortResponseKind::SocketError, EADDRNOTAVAIL, {}, PortScanClock::now()};
    assert(connect_probe.assess(local_address, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Unknown);
    assert(reason == ScanReason::LocalAddressUnavailable);

    PortResponse reset{1U, "127.0.0.1", PortResponseKind::SocketError, ECONNRESET, {}, PortScanClock::now()};
    assert(connect_probe.assess(reset, connect_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Unknown);

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

    PortResponse syn_unreachable{7U, "127.0.0.1", PortResponseKind::Unreachable, 0, {}, PortScanClock::now()};
    assert(syn_probe.assess(syn_unreachable, syn_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Unreachable);
    assert(reason == ScanReason::NetworkUnreachable);

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

    struct RawScanCase final {
        ScanProbeType type;
        std::uint16_t flags;
        PortState timeout_state;
    };
    const std::vector<RawScanCase> raw_cases{
        {ScanProbeType::TcpNull, 0U, PortState::OpenOrFiltered},
        {ScanProbeType::TcpFin, static_cast<std::uint16_t>(skan::packet::TcpFlag::Fin), PortState::OpenOrFiltered},
        {ScanProbeType::TcpXmas,
         skan::packet::TcpFlag::Fin | skan::packet::TcpFlag::Psh | skan::packet::TcpFlag::Urg,
         PortState::OpenOrFiltered},
        {ScanProbeType::TcpWindow, static_cast<std::uint16_t>(skan::packet::TcpFlag::Ack), PortState::Filtered},
        {ScanProbeType::TcpMaimon,
         skan::packet::TcpFlag::Fin | skan::packet::TcpFlag::Ack,
         PortState::OpenOrFiltered}};

    PortProbeId raw_id = 20U;
    for (const RawScanCase &raw_case : raw_cases) {
        TcpFlagProbe raw_probe(raw_case.type);
        assert(raw_probe.type() == raw_case.type);
        assert(raw_probe.timeout_state() == raw_case.timeout_state);
        assert(raw_probe.timeout_reason() == ScanReason::Timeout);

        PortSubmission raw_submission;
        PortScanConfig raw_config;
        raw_config.method = raw_case.type;
        assert(raw_probe.build(raw_id, host, port, raw_config, raw_submission) == skan::core::StatusCode::Ok);
        const auto raw_request = skan::packet::TCP::parse(raw_submission.packet);
        assert(raw_request.has_value());
        assert(raw_request->flags() == raw_case.flags);

        skan::packet::TCP raw_rst;
        raw_rst.set_source_port(port.number);
        raw_rst.set_destination_port(raw_submission.source_port);
        raw_rst.set_sequence_number(333U);
        raw_rst.set_acknowledgment_number(0U);
        raw_rst.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Rst));
        raw_rst.set_window(0U);
        PortResponse raw_rst_response{raw_id, "127.0.0.1", PortResponseKind::Packet, 0,
                                      serialize_tcp(raw_rst), PortScanClock::now()};
        state = PortState::Unknown;
        reason = ScanReason::InternalError;
        assert(raw_probe.assess(raw_rst_response, raw_submission, state, reason) == skan::core::StatusCode::Ok);
        assert(state == PortState::Closed);
        assert(reason == (raw_case.type == ScanProbeType::TcpWindow ? ScanReason::RstWindowZero : ScanReason::Rst));

        PortResponse raw_unreachable{raw_id, "127.0.0.1", PortResponseKind::Unreachable, 0, {},
                                     PortScanClock::now()};
        assert(raw_probe.assess(raw_unreachable, raw_submission, state, reason) == skan::core::StatusCode::Ok);
        assert(state == PortState::Unreachable);
        assert(reason == ScanReason::NetworkUnreachable);
        ++raw_id;
    }

    TcpFlagProbe window_probe(ScanProbeType::TcpWindow);
    PortSubmission window_submission;
    PortScanConfig window_config;
    window_config.method = ScanProbeType::TcpWindow;
    assert(window_probe.build(50U, host, port, window_config, window_submission) == skan::core::StatusCode::Ok);
    skan::packet::TCP window_rst;
    window_rst.set_source_port(port.number);
    window_rst.set_destination_port(window_submission.source_port);
    window_rst.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Rst));
    window_rst.set_window(2048U);
    PortResponse window_response{50U, "127.0.0.1", PortResponseKind::Packet, 0,
                                 serialize_tcp(window_rst), PortScanClock::now()};
    assert(window_probe.assess(window_response, window_submission, state, reason) == skan::core::StatusCode::Ok);
    assert(state == PortState::Open);
    assert(reason == ScanReason::RstWindowOpen);

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
