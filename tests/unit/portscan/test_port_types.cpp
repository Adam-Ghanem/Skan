#include <cassert>
#include <string>

#include "portscan/port_types.hpp"

int main()
{
    using namespace skan::portscan;

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
    assert(parse_tcp_ports("1,,2").status == skan::core::StatusCode::InvalidArgument);
    assert(parse_tcp_ports("abc").status == skan::core::StatusCode::InvalidArgument);

    const std::vector<Port> defaults = default_tcp_ports();
    assert(defaults.size() == 3U);
    assert(defaults[0].number == 22U);
    assert(defaults[1].number == 80U);
    assert(defaults[2].number == 443U);
    assert(std::string{port_state_name(PortState::Open)} == "OPEN");
    assert(std::string{scan_probe_type_name(ScanProbeType::TcpSyn)} == "syn");
    assert(std::string{scan_reason_name(ScanReason::Timeout)} == "TIMEOUT");
    return 0;
}
