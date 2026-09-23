#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
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
    assert(skan::orchestrator::ScanConfig{}.retries == 1U);

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

    // The default CLI configuration must reach the port scheduler so one
    // transient refusal is confirmed before CLOSED is published.
    skan::io::IOEngine retry_engine;
    auto retry_config = config();
    retry_config.port_method = skan::portscan::ScanProbeType::TcpConnect;
    retry_config.ports = {22U};
    skan::portscan::RecordingPortScanTransport *retry_transport = nullptr;
    skan::orchestrator::ScanStageDependencies retry_dependencies;
    retry_dependencies.port_transport =
        [&retry_transport](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &)
        -> std::unique_ptr<skan::portscan::PortScanTransport> {
        auto transport = std::make_unique<skan::portscan::RecordingPortScanTransport>();
        retry_transport = transport.get();
        return transport;
    };
    retry_dependencies.after_port_submit =
        [&retry_transport](skan::portscan::PortScanScheduler &scheduler) {
        assert(retry_transport != nullptr);
        const auto first = retry_transport->submissions().front();
        retry_transport->deliver({first.id, first.target,
                                  skan::portscan::PortResponseKind::ConnectionRefused,
                                  ECONNREFUSED, {}, skan::portscan::PortScanClock::now()});
        assert(retry_transport->submissions().size() == 1U);
        std::this_thread::sleep_for(std::chrono::milliseconds{260});
        assert(scheduler.run_once(0) == skan::core::StatusCode::Ok);
        assert(retry_transport->submissions().size() == 2U);
        const auto confirmation = retry_transport->submissions().back();
        retry_transport->deliver({confirmation.id, confirmation.target,
                                  skan::portscan::PortResponseKind::Connected,
                                  0, {}, skan::portscan::PortScanClock::now()});
    };
    skan::orchestrator::PortScanStage retry_stage(
        retry_engine, retry_config, retry_config.targets.front(), &retry_dependencies);
    assert(retry_stage.start().success());
    assert(retry_stage.results().size() == 1U);
    assert(retry_stage.results().front().state == skan::portscan::PortState::Open);
    assert(retry_stage.results().front().retry_count == 1U);
    return 0;
}
