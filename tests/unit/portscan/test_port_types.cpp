#include <array>
#include <cassert>
#include <string>

#include "portscan/port_types.hpp"

int main()
{
    using namespace skan::portscan;
    static_assert(static_cast<int>(ScanProbeType::Udp) == 2);
    static_assert(static_cast<int>(ScanReason::Timeout) == 6);
    static_assert(static_cast<int>(ScanReason::UnsupportedProtocol) == 22);

    const PortSelection parsed = parse_tcp_ports("443,80,1000-1002,80");
    assert(parsed.status == skan::core::StatusCode::Ok);
    assert(parsed.ports.size() == 5U);
    assert(parsed.ports[0].number == 80U);
    assert(parsed.ports[1].number == 443U);
    assert(parsed.ports[2].number == 1000U);
    assert(parsed.ports[3].number == 1001U);
    assert(parsed.ports[4].number == 1002U);
    for (const Port &port : parsed.ports) {
        assert(port.protocol == Protocol::Tcp);
        assert(port.number != 0U);
    }

    assert(parse_tcp_ports("1").ports.front().number == 1U);
    assert(parse_tcp_ports("65535").ports.front().number == 65535U);
    assert(parse_tcp_ports("").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("0").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("65536").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("10-9").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("10-").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("-10").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("1-2-3").status == skan::core::StatusCode::InvalidArgument);
    const PortSelection all_ports = parse_tcp_ports("1-65535");
    assert(all_ports.status == skan::core::StatusCode::Ok);
    assert(all_ports.ports.size() == 65535U);
    assert(all_ports.ports.front().number == 1U);
    assert(all_ports.ports.back().number == 65535U);
    assert(parse_tcp_ports("1,,2").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("abc").status == skan::core::StatusCode::InvalidArgument);

    const std::vector<Port> defaults = default_tcp_ports();
    assert(defaults.size() == 3U);
    assert(defaults[0].number == 22U);
    assert(defaults[1].number == 80U);
    assert(defaults[2].number == 443U);
    assert(std::string{port_state_name(PortState::Open)} == "OPEN");
    assert(std::string{scan_probe_type_name(ScanProbeType::TcpSyn)} == "syn");
    assert(std::string{scan_probe_type_name(ScanProbeType::TcpAck)} == "ack");
    assert(std::string{scan_reason_name(ScanReason::Timeout)} == "TIMEOUT");
    assert(std::string{scan_reason_name(ScanReason::AckRst)} == "ACK_RST");
    assert(std::string{scan_reason_name(ScanReason::AckTimeout)} == "ACK_TIMEOUT");
    assert(std::string{scan_reason_name(ScanReason::ConflictingEvidence)} == "CONFLICTING_EVIDENCE");
    assert(std::string{scan_reason_name(ScanReason::IcmpProtocolUnreachable)} == "ICMP_PROTOCOL_UNREACHABLE");

    constexpr std::array<Protocol, 2U> protocols{Protocol::Tcp, Protocol::Udp};
    constexpr std::array<ScanProbeType, 4U> probes{
        ScanProbeType::TcpConnect, ScanProbeType::TcpSyn, ScanProbeType::Udp, ScanProbeType::TcpAck};
    constexpr std::array<PortState, 8U> states{
        PortState::Open, PortState::Closed, PortState::Filtered, PortState::Unknown,
        PortState::OpenOrFiltered, PortState::Unfiltered, PortState::Error, PortState::Unreachable};
    constexpr std::array<ScanReason, 27U> reasons{
        ScanReason::ImmediateSuccess, ScanReason::ConnectionRefused, ScanReason::NetworkUnreachable,
        ScanReason::LocalAddressUnavailable, ScanReason::SynAck, ScanReason::Rst, ScanReason::Timeout,
        ScanReason::SocketError, ScanReason::MalformedResponse, ScanReason::UnrelatedResponse,
        ScanReason::InvalidTarget, ScanReason::InvalidPort, ScanReason::UnsupportedMethod,
        ScanReason::CapabilityUnavailable, ScanReason::InternalError, ScanReason::UdpResponse,
        ScanReason::IcmpPortUnreachable, ScanReason::IcmpAdministrativelyProhibited,
        ScanReason::IcmpNetworkUnreachable, ScanReason::UdpTimeout, ScanReason::DuplicateResponse,
        ScanReason::LateResponse, ScanReason::UnsupportedProtocol, ScanReason::AckRst,
        ScanReason::AckTimeout, ScanReason::ConflictingEvidence, ScanReason::IcmpProtocolUnreachable};

    const auto expected = [](Protocol protocol, ScanProbeType probe, PortState state, ScanReason reason) {
        if ((protocol == Protocol::Udp) != (probe == ScanProbeType::Udp)) return false;
        if (state == PortState::Open)
            return (probe == ScanProbeType::TcpConnect && reason == ScanReason::ImmediateSuccess) ||
                   (probe == ScanProbeType::TcpSyn && reason == ScanReason::SynAck) ||
                   (probe == ScanProbeType::Udp && reason == ScanReason::UdpResponse);
        if (state == PortState::Closed)
            return (probe == ScanProbeType::TcpConnect && reason == ScanReason::ConnectionRefused) ||
                   (probe == ScanProbeType::TcpSyn && reason == ScanReason::Rst) ||
                   (probe == ScanProbeType::Udp && reason == ScanReason::IcmpPortUnreachable);
        if (state == PortState::Filtered)
            return (probe == ScanProbeType::TcpConnect && reason == ScanReason::Timeout) ||
                   (probe == ScanProbeType::TcpSyn &&
                    (reason == ScanReason::Timeout || reason == ScanReason::IcmpAdministrativelyProhibited ||
                     reason == ScanReason::IcmpPortUnreachable || reason == ScanReason::IcmpProtocolUnreachable)) ||
                   (probe == ScanProbeType::TcpAck &&
                    (reason == ScanReason::AckTimeout || reason == ScanReason::IcmpAdministrativelyProhibited ||
                     reason == ScanReason::IcmpPortUnreachable || reason == ScanReason::IcmpProtocolUnreachable)) ||
                   (probe == ScanProbeType::Udp && reason == ScanReason::IcmpAdministrativelyProhibited);
        if (state == PortState::Unknown) return reason == ScanReason::ConflictingEvidence;
        if (state == PortState::OpenOrFiltered)
            return probe == ScanProbeType::Udp && reason == ScanReason::UdpTimeout;
        if (state == PortState::Unfiltered)
            return probe == ScanProbeType::TcpAck && reason == ScanReason::AckRst;
        if (state == PortState::Error)
            return reason == ScanReason::LocalAddressUnavailable || reason == ScanReason::SocketError ||
                   reason == ScanReason::InvalidTarget || reason == ScanReason::InvalidPort ||
                   reason == ScanReason::UnsupportedMethod || reason == ScanReason::CapabilityUnavailable ||
                   reason == ScanReason::InternalError || reason == ScanReason::UnsupportedProtocol;
        return state == PortState::Unreachable &&
               ((probe == ScanProbeType::TcpConnect && reason == ScanReason::NetworkUnreachable) ||
                (probe != ScanProbeType::TcpConnect && reason == ScanReason::IcmpNetworkUnreachable));
    };

    std::size_t evaluated = 0U;
    for (const Protocol protocol : protocols) {
        for (const ScanProbeType probe : probes) {
            for (const PortState state : states) {
                for (const ScanReason reason : reasons) {
                    assert(valid_port_result_semantics(protocol, probe, state, reason) ==
                           expected(protocol, probe, state, reason));
                    ++evaluated;
                }
            }
        }
    }
    assert(evaluated == 1728U);
    return 0;
}
