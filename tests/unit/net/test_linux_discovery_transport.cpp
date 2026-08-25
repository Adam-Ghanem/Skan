#include <cassert>
#include <iostream>

#include "io/io_engine.hpp"
#include "net/linux_discovery_transport.hpp"

int main()
{
    skan::io::IOEngine io_engine;
    assert(io_engine.initialization_status() == skan::core::StatusCode::Ok);

    skan::net::LinuxDiscoveryTransport invalid(io_engine, {});
    assert(invalid.open().status == skan::net::NetworkScanStatus::InvalidConfiguration);
    assert(!invalid.is_open());

    skan::net::LinuxDiscoveryTransport transport(io_engine, "lo");
    const skan::net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        std::cout << "SKIPPED: Linux discovery transport unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    assert(transport.capture_file_descriptor() >= 0);
    assert(transport.transport_file_descriptor() >= 0);
    transport.close();
    transport.close();
    assert(!transport.is_open());
    return 0;
}
