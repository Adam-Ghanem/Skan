#include <algorithm>
#include <cassert>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "orchestrator/scan_pipeline.hpp"

namespace {

class QueuedPortTransport final : public skan::portscan::PortScanTransport {
public:
    struct Pending final {
        skan::portscan::PortProbeId id{0U};
        skan::portscan::PortResponseCallback callback;
        std::string target;
    };

    explicit QueuedPortTransport(std::shared_ptr<std::vector<Pending>> pending)
        : pending_(std::move(pending))
    {
    }
    bool supports(skan::portscan::ScanProbeType) const noexcept override { return true; }
    skan::core::StatusCode submit(
        const skan::portscan::PortSubmission &submission,
        skan::portscan::PortResponseCallback callback) override
    {
        pending_->push_back({submission.id, std::move(callback), submission.target});
        return skan::core::StatusCode::Ok;
    }
    skan::core::StatusCode cancel(skan::portscan::PortProbeId) noexcept override { return skan::core::StatusCode::Ok; }
    void flush()
    {
        while (!pending_->empty()) {
            Pending item = std::move(pending_->front());
            pending_->erase(pending_->begin());
            item.callback({item.id, item.target, skan::portscan::PortResponseKind::Connected, 0, {},
                           skan::portscan::PortScanClock::now()});
        }
    }
private:
    std::shared_ptr<std::vector<Pending>> pending_;
};

} // namespace

int main()
{
    skan::orchestrator::ScanConfig config;
    config.targets = {{"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}}};
    config.transport = skan::orchestrator::ScanTransport::Connect;
    config.port_method = skan::portscan::ScanProbeType::TcpConnect;
    config.ports = {80U};
    config.timeout = std::chrono::milliseconds{10};
    config.service_detection_enabled = true;
    config.os_detection_enabled = true;
    config.output_format = skan::output::OutputFormat::Json;

    auto port_pending = std::make_shared<std::vector<QueuedPortTransport::Pending>>();
    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.port_transport = [port_pending](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &) {
        return std::make_unique<QueuedPortTransport>(port_pending);
    };
    dependencies.after_port_submit = [port_pending](skan::portscan::PortScanScheduler &) {
        QueuedPortTransport transport(port_pending);
        transport.flush();
    };
    dependencies.after_service_submit = [](skan::detect::ServiceDetector &detector) {
        (void)detector.receive({1U, "127.0.0.1", skan::detect::ServiceResponseKind::Closed, 0, {}, false,
                                skan::detect::DetectionClock::now()});
    };
    std::vector<skan::orchestrator::ScanEventType> events;
    skan::orchestrator::ScanPipeline pipeline(config, [&](const skan::orchestrator::ScanEvent &event) {
        events.push_back(event.type);
    }, std::move(dependencies));
    std::ostringstream output;
    assert(pipeline.run(output) == skan::core::StatusCode::Ok);
    assert(pipeline.state() == skan::orchestrator::PipelineState::Completed);
    assert(pipeline.report().has_value());
    const auto summary = skan::output::calculate_summary(*pipeline.report());
    assert(summary.open_ports == 1U);
    assert(summary.services_detected == 0U);
    assert(summary.os_matches == 0U);
    assert(!pipeline.report()->warnings.empty());
    const auto service_started = std::find(events.begin(), events.end(), skan::orchestrator::ScanEventType::StageStarted);
    assert(service_started != events.end());
    assert(output.str().find("\"warnings\"") != std::string::npos);
    return 0;
}
