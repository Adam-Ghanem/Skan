#include <cassert>
#include <iostream>
#include <string>

#include "io/io_engine.hpp"
#include "net/linux_os_probe_transport.hpp"
#include "net/network_scan_transport.hpp"

int main()
{
    using namespace skan;
    io::IOEngine engine;
    assert(engine.initialization_status() == core::StatusCode::Ok);
    net::LinuxOSProbeTransport transport(
        engine, net::NetworkScanConfig{"lo", 65535U, true, std::nullopt});
    const net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        if (opened.status == net::NetworkScanStatus::PermissionDenied ||
            opened.status == net::NetworkScanStatus::NotSupported ||
            opened.status == net::NetworkScanStatus::InterfaceNotFound) {
            std::cout << "SKIPPED: Linux OS raw capability unavailable: " << opened.message << '\n';
            return 0;
        }
        std::cerr << "unexpected Linux OS transport failure: " << net::network_scan_status_name(opened.status)
                  << " " << opened.message << '\n';
        return 1;
    }
    assert(transport.is_open());
    assert(!transport.local_source_address().empty());
    transport.close();
    assert(!transport.is_open());
    return 0;
}
