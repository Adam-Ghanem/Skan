#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

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

skan::portscan::PortResult open_tcp_port(const char *target, std::uint16_t port)
{
    skan::portscan::PortResult result;
    result.target = target;
    result.port = {port, skan::portscan::Protocol::Tcp};
    result.state = skan::portscan::PortState::Open;
    result.probe = skan::portscan::ScanProbeType::TcpConnect;
    return result;
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
    assert(!os_stage.unavailable());
    assert(os_stage.detection_result().has_value());
    assert(os_stage.detection_result()->state == skan::osdetect::OSDetectionState::Partial);

    // Service detection must not inherit an aggressively short TCP port-scan
    // timeout. The built-in HTTP probe is allowed to wait for service evidence
    // using the service-stage timeout budget instead.
    skan::io::IOEngine service_engine;
    assert(service_engine.initialization_status() == skan::core::StatusCode::Ok);
    auto service_config = config();
    service_config.max_probes_per_port = 1U;

    skan::detect::RecordingServiceTransport *recording_transport = nullptr;
    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.service_transport =
        [&recording_transport](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &)
        -> std::unique_ptr<skan::detect::ServiceTransport> {
        auto transport = std::make_unique<skan::detect::RecordingServiceTransport>();
        recording_transport = transport.get();
        return transport;
    };
    dependencies.after_service_submit =
        [&service_engine, &recording_transport](skan::detect::ServiceDetector &) {
        assert(recording_transport != nullptr);
        assert(recording_transport->submissions().size() == 1U);
        const auto submission = recording_transport->submissions().front();
        const auto timer = service_engine.schedule(
            std::chrono::milliseconds{5},
            [recording_transport, submission]() {
                const std::string response =
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.29\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const std::vector<std::uint8_t> bytes(response.begin(), response.end());
                recording_transport->deliver({
                    submission.id,
                    submission.target,
                    skan::detect::ServiceResponseKind::Data,
                    0,
                    bytes,
                    false,
                    skan::detect::DetectionClock::now()});
            });
        assert(timer != 0U);
    };

    skan::orchestrator::ServiceDetectionStage delayed_service_stage(
        service_engine, service_config, &dependencies);
    assert(delayed_service_stage.start({open_tcp_port("127.0.0.1", 80U)}).success());
    assert(delayed_service_stage.results().size() == 1U);
    assert(delayed_service_stage.results().front().state == skan::detect::DetectionState::Detected);
    assert(delayed_service_stage.results().front().service == "http");
    assert(delayed_service_stage.results().front().version == "2.4.29");
    return 0;
}
