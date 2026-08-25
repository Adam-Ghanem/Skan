#include <cassert>
#include <iostream>
#include <optional>

#include "net/udp_network_scan_transport.hpp"

int main()
{
    using namespace skan;
    io::IOEngine engine;
    assert(engine.initialization_status() == core::StatusCode::Ok);
    net::LinuxUDPScanTransport transport(engine, net::NetworkScanConfig{
        "lo", 65535U, true, std::array<std::uint8_t, 6U>{}});
    const net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        assert(opened.status == net::NetworkScanStatus::PermissionDenied ||
               opened.status == net::NetworkScanStatus::NotSupported ||
               opened.status == net::NetworkScanStatus::InterfaceNotFound ||
               opened.status == net::NetworkScanStatus::SystemError);
        std::cout << "SKIPPED: Linux UDP raw capability unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    assert(transport.supports());
    transport.close();
    assert(!transport.is_open());
    std::cout << "Linux UDP transport capability test passed\n";
    return 0;
}
