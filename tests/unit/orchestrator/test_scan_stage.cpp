#include <cassert>

#include "orchestrator/scan_stage.hpp"

namespace {

skan::orchestrator::ScanConfig config()
{
    skan::orchestrator::ScanConfig value;
    value.targets = {{"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}}};
    value.transport = skan::orchestrator::ScanTransport::Offline;
    value.port_method = skan::portscan::ScanProbeType::TcpSyn;
    value.ports = {80U};
    value.timeout = std::chrono::milliseconds{1};
    return value;
}

} // namespace

int main()
{
    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);
    const auto scan_config = config();
    const skan::core::Target target = scan_config.targets.front();

    skan::orchestrator::PortScanStage port_stage(engine, scan_config, target);
    assert(port_stage.start().success());
    assert(port_stage.results().size() == 1U);

    skan::orchestrator::ServiceDetectionStage service_stage(engine, scan_config);
    assert(service_stage.start(port_stage.results()).success());
    assert(service_stage.results().empty());

    skan::orchestrator::OSDetectionStage os_stage(engine, scan_config, target);
    assert(os_stage.start(port_stage.results(), {}).success());
    assert(os_stage.unavailable());
    return 0;
}
