#include <cassert>
#include <iostream>

#include "io/io_engine.hpp"
#include "net/interface.hpp"
#include "net/network_scan_transport.hpp"

int main()
{
    using skan::core::ExitCode;
    using skan::core::StatusCode;
    using skan::net::NetworkScanStatus;
    using skan::net::network_scan_status_to_exit_code;
    using skan::net::network_scan_status_to_status_code;

    assert(network_scan_status_to_status_code(NetworkScanStatus::Success) == StatusCode::Ok);
    assert(network_scan_status_to_status_code(NetworkScanStatus::InvalidConfiguration) == StatusCode::InvalidArgument);
    assert(network_scan_status_to_status_code(NetworkScanStatus::InterfaceNotFound) == StatusCode::InvalidArgument);
    assert(network_scan_status_to_status_code(NetworkScanStatus::RoutingUnavailable) == StatusCode::IoError);
    assert(network_scan_status_to_status_code(NetworkScanStatus::PermissionDenied) == StatusCode::PermissionDenied);
    assert(network_scan_status_to_status_code(NetworkScanStatus::NotSupported) == StatusCode::PermissionDenied);
    assert(network_scan_status_to_status_code(NetworkScanStatus::NotOpen) == StatusCode::IoError);
    assert(network_scan_status_to_status_code(NetworkScanStatus::SystemError) == StatusCode::IoError);
    assert(network_scan_status_to_status_code(static_cast<NetworkScanStatus>(999)) == StatusCode::IoError);

    assert(network_scan_status_to_exit_code(NetworkScanStatus::Success) == ExitCode::Success);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::InvalidConfiguration) == ExitCode::Usage);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::InterfaceNotFound) == ExitCode::Usage);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::RoutingUnavailable) == ExitCode::Runtime);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::PermissionDenied) == ExitCode::Permission);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::NotSupported) == ExitCode::Permission);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::NotOpen) == ExitCode::Runtime);
    assert(network_scan_status_to_exit_code(NetworkScanStatus::SystemError) == ExitCode::Runtime);
    assert(network_scan_status_to_exit_code(static_cast<NetworkScanStatus>(999)) == ExitCode::Runtime);

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
        assert(opened.category != skan::net::PreflightCategory::Ready);
        assert(opened.family == skan::core::AddressFamily::IPv4 || opened.family == skan::core::AddressFamily::IPv6);
        assert(!opened.message.empty());
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
