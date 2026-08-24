#include <cassert>
#include <cstdint>
#include <string>

#include "core/types.hpp"

int main()
{
    using skan::core::Host;
    using skan::core::Port;
    using skan::core::PortState;
    using skan::core::Protocol;
    using skan::core::ScanResult;
    using skan::core::Target;

    const Host host{"192.0.2.10", std::string{"example.test"}, true};
    const Port port{443U, Protocol::Tcp, PortState::Open, std::string{"https"}};
    const Target target{"example.test", {host}};
    const ScanResult result{host, {port}, std::string{"phase-0"}};

    assert(host.address == "192.0.2.10");
    assert(host.hostname.has_value());
    assert(host.hostname.value() == "example.test");
    assert(host.is_up);
    assert(port.number == static_cast<std::uint16_t>(443U));
    assert(port.protocol == Protocol::Tcp);
    assert(port.state == PortState::Open);
    assert(port.service.has_value());
    assert(port.service.value() == "https");
    assert(target.original_specification == "example.test");
    assert(target.resolved_hosts.size() == 1U);
    assert(result.ports.size() == 1U);
    assert(result.ports.front().number == static_cast<std::uint16_t>(443U));
    assert(result.metadata.has_value());
    assert(result.metadata.value() == "phase-0");

    return 0;
}
