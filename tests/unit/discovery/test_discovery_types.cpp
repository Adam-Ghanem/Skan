#include <cassert>
#include <string>

#include "discovery/discovery_types.hpp"

int main()
{
    using namespace skan::discovery;
    assert(std::string{host_state_name(HostState::Unknown)} == "UNKNOWN");
    assert(std::string{host_state_name(HostState::Up)} == "UP");
    assert(std::string{host_state_name(HostState::Unreachable)} == "UNREACHABLE");
    assert(std::string{probe_type_name(ProbeType::Tcp)} == "TCP");
    assert(std::string{discovery_reason_name(DiscoveryReason::Timeout)} == "TIMEOUT");
    assert(std::string{discovery_reason_name(DiscoveryReason::Unreachable)} == "UNREACHABLE");

    assert(parse_ipv4_address("127.0.0.1").value() == 0x7F000001U);
    assert(parse_ipv4_address("192.0.2.10").value() == 0xC000020AU);
    assert(!parse_ipv4_address("").has_value());
    assert(!parse_ipv4_address("127.0.0").has_value());
    assert(!parse_ipv4_address("127.0.0.256").has_value());
    assert(!parse_ipv4_address("127.0.0.1.2").has_value());
    assert(!parse_ipv4_address("127.0.0.x").has_value());

    DiscoveryConfig config;
    assert(config.tcp_port == kDefaultTcpDiscoveryPort);
    assert(config.timeout == kDefaultDiscoveryTimeout);
    assert(config.max_outstanding == kDefaultMaxOutstanding);
    return 0;
}
