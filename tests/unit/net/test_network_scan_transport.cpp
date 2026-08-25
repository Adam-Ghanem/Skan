#include <cassert>
#include <iostream>

#include "io/io_engine.hpp"
#include "net/interface.hpp"
#include "net/network_scan_transport.hpp"

int main()
{
    skan::io::IOEngine io_engine;
    assert(io_engine.initialization_status() == skan::core::StatusCode::Ok);

    skan::net::LinuxNetworkScanTransport invalid(
        io_engine, skan::net::NetworkScanConfig{});
    assert(!invalid.supports(skan::portscan::ScanProbeType::TcpSyn));
    assert(invalid.open().status == skan::net::NetworkScanStatus::InvalidConfiguration);

    if (!skan::net::find_interface("lo").has_value()) {
        std::cout << "SKIPPED: loopback interface unavailable\n";
        return 0;
    }
    skan::net::LinuxNetworkScanTransport transport(
        io_engine, skan::net::NetworkScanConfig{"lo", 65535U, true, std::nullopt});
    const skan::net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        std::cout << "SKIPPED: Linux network scan transport unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    assert(transport.supports(skan::portscan::ScanProbeType::TcpSyn));
    assert(transport.session().active);
    assert(transport.session().id != 0U);
    assert(transport.capture_file_descriptor() >= 0);
    assert(transport.transport_file_descriptor() >= 0);
    transport.close();
    transport.close();
    assert(!transport.is_open());
    assert(!transport.supports(skan::portscan::ScanProbeType::TcpSyn));
    return 0;
}
