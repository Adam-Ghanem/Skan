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

    explicit QueuedPortTransport(std::shared_ptr<std::vector<Pending>> queue)
        : queue_(std::move(queue))
    {
    }

    bool supports(skan::portscan::ScanProbeType) const noexcept override { return true; }
    skan::core::StatusCode submit(
        const skan::portscan::PortSubmission &submission,
        skan::portscan::PortResponseCallback callback) override
    {
        queue_->push_back({submission.id, std::move(callback), submission.target});
        return skan::core::StatusCode::Ok;
    }
    skan::core::StatusCode cancel(skan::portscan::PortProbeId) noexcept override
    {
        return skan::core::StatusCode::Ok;
    }

    void flush()
    {
        while (!queue_->empty()) {
            Pending pending = std::move(queue_->front());
            queue_->erase(queue_->begin());
            pending.callback({pending.id, pending.target, skan::portscan::PortResponseKind::Connected, 0, {},
                              skan::portscan::PortScanClock::now()});
        }
    }

private:
    std::shared_ptr<std::vector<Pending>> queue_;
};

} // namespace

int main()
{
    skan::orchestrator::ScanConfig config;
    config.transport = skan::orchestrator::ScanTransport::Connect;
    config.port_method = skan::portscan::ScanProbeType::TcpConnect;
    config.timeout = std::chrono::milliseconds{20};
    config.max_parallelism = 64U;
    config.output_format = skan::output::OutputFormat::Grepable;
    for (unsigned int host_index = 1U; host_index <= 100U; ++host_index) {
        const std::string address = "192.0.2." + std::to_string(host_index);
        config.targets.push_back({address, {{address, std::nullopt, false}}});
    }
    for (unsigned int port = 1000U; port < 1100U; ++port) {
        config.ports.push_back(static_cast<std::uint16_t>(port));
    }

    auto queue = std::make_shared<std::vector<QueuedPortTransport::Pending>>();
    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.port_transport = [queue](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &) {
        return std::make_unique<QueuedPortTransport>(queue);
    };
    dependencies.after_port_submit = [queue](skan::portscan::PortScanScheduler &) {
        QueuedPortTransport transport(queue);
        transport.flush();
    };
    skan::orchestrator::ScanPipeline pipeline(config, {}, std::move(dependencies));
    std::ostringstream output;
    assert(pipeline.run(output) == skan::core::StatusCode::Ok);
    assert(pipeline.state() == skan::orchestrator::PipelineState::Completed);
    assert(pipeline.report().has_value());
    const auto summary = skan::output::calculate_summary(*pipeline.report());
    assert(summary.hosts == 100U);
    assert(summary.ports_scanned == 10000U);
    assert(summary.open_ports == 10000U);
    assert(output.str().find("ports_scanned=10000") != std::string::npos);
    return 0;
}
