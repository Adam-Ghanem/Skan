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
    assert(!invalid.supports(skan::portscan::ScanProbeType::TcpNull));
    assert(!invalid.supports(skan::portscan::ScanProbeType::TcpConnect));
    assert(!invalid.supports(skan::portscan::ScanProbeType::Udp));
    assert(invalid.open().status == skan::net::NetworkScanStatus::InvalidConfiguration);

    if (!skan::net::find_interface("lo").has_value()) {
        std::cout << "SKIPPED: loopback interface unavailable\n";
        return 0;
    }
    skan::net::LinuxNetworkScanTransport transport(
        io_engine, skan::net::NetworkScanConfig{"lo", 65535U, true, std::nullopt});
    const skan::net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        assert(opened.category != skan::net::PreflightCategory::Ready);
        assert(opened.family == skan::core::AddressFamily::IPv4 || opened.family == skan::core::AddressFamily::IPv6);
        assert(!opened.message.empty());
        std::cout << "SKIPPED: Linux network scan transport unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    const skan::portscan::ScanProbeType raw_methods[] = {
        skan::portscan::ScanProbeType::TcpSyn,
        skan::portscan::ScanProbeType::TcpNull,
        skan::portscan::ScanProbeType::TcpFin,
        skan::portscan::ScanProbeType::TcpXmas,
        skan::portscan::ScanProbeType::TcpWindow,
        skan::portscan::ScanProbeType::TcpMaimon};
    for (const skan::portscan::ScanProbeType method : raw_methods) {
        assert(transport.supports(method));
    }
    assert(!transport.supports(skan::portscan::ScanProbeType::TcpConnect));
    assert(!transport.supports(skan::portscan::ScanProbeType::Udp));
    assert(transport.session().active);
    assert(transport.session().id != 0U);
    assert(transport.capture_file_descriptor() >= 0);
    assert(transport.transport_file_descriptor() >= 0);
    transport.close();
    transport.close();
    assert(!transport.is_open());
    for (const skan::portscan::ScanProbeType method : raw_methods) {
        assert(!transport.supports(method));
    }
    assert(!transport.supports(skan::portscan::ScanProbeType::TcpConnect));
    assert(!transport.supports(skan::portscan::ScanProbeType::Udp));
    return 0;
}
