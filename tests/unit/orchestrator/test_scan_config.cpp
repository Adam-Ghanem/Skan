#include <cassert>

#include "orchestrator/scan_config.hpp"

namespace {

skan::orchestrator::ScanConfig valid_config()
{
    skan::orchestrator::ScanConfig config;
    config.targets.push_back({"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}});
    return config;
}

} // namespace

int main()
{
    skan::orchestrator::ScanConfig empty;
    assert(empty.validate() == skan::core::StatusCode::InvalidArgument);

    const skan::orchestrator::ScanConfig defaults = valid_config();
    assert(defaults.validate() == skan::core::StatusCode::Ok);
    assert(defaults.transport == skan::orchestrator::ScanTransport::Connect);
    assert(defaults.port_scan_enabled);
    assert(!defaults.discovery_enabled);
    assert(!defaults.service_detection_enabled);
    assert(!defaults.os_detection_enabled);

    auto invalid = valid_config();
    invalid.min_parallelism = 4U;
    invalid.max_parallelism = 2U;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);

    invalid = valid_config();
    invalid.timeout = std::chrono::milliseconds{0};
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);

    invalid = valid_config();
    invalid.ports = {0U};
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);

    invalid = valid_config();
    invalid.transport = skan::orchestrator::ScanTransport::Linux;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid.interface_name = "lo";
    invalid.port_method = skan::portscan::ScanProbeType::TcpConnect;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid.port_method = skan::portscan::ScanProbeType::TcpSyn;
    assert(invalid.validate() == skan::core::StatusCode::Ok);

    invalid = valid_config();
    invalid.discovery_enabled = true;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid.transport = skan::orchestrator::ScanTransport::Offline;
    assert(invalid.validate() == skan::core::StatusCode::Ok);

    invalid = valid_config();
    invalid.udp_enabled = true;
    invalid.transport = skan::orchestrator::ScanTransport::Offline;
    invalid.udp_ports = {53U, 161U};
    assert(invalid.validate() == skan::core::StatusCode::Ok);
    invalid.transport = skan::orchestrator::ScanTransport::Connect;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid.transport = skan::orchestrator::ScanTransport::Offline;
    invalid.udp_ports = {0U};
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);

    invalid = valid_config();
    invalid.max_response_bytes = 0U;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid = valid_config();
    invalid.max_probes_per_port = 0U;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    return 0;
}
