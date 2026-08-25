#include <cassert>
#include <memory>
#include <sstream>
#include <utility>
#include <vector>

#include "orchestrator/scan_pipeline.hpp"

namespace {

class InjectedPortTransport final : public skan::portscan::PortScanTransport {
public:
    struct Pending final {
        skan::portscan::PortProbeId id{0U};
        skan::portscan::PortResponseCallback callback;
        std::string target;
    };

    explicit InjectedPortTransport(std::shared_ptr<std::vector<Pending>> pending)
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

    skan::core::StatusCode cancel(skan::portscan::PortProbeId) noexcept override
    {
        return skan::core::StatusCode::Ok;
    }

    void flush(skan::portscan::PortScanScheduler &scheduler)
    {
        while (!pending_->empty()) {
            Pending pending = std::move(pending_->front());
            pending_->erase(pending_->begin());
            pending.callback({pending.id, pending.target, skan::portscan::PortResponseKind::Connected, 0, {},
                              skan::portscan::PortScanClock::now()});
            (void)scheduler;
        }
    }

private:
    std::shared_ptr<std::vector<Pending>> pending_;
};

skan::orchestrator::ScanConfig config()
{
    skan::orchestrator::ScanConfig value;
    value.targets = {
        {"targets", {{"192.0.2.2", std::nullopt, false}, {"192.0.2.1", std::nullopt, false}}}};
    value.transport = skan::orchestrator::ScanTransport::Connect;
    value.port_method = skan::portscan::ScanProbeType::TcpConnect;
    value.ports = {80U, 22U};
    value.timeout = std::chrono::milliseconds{20};
    value.max_parallelism = 2U;
    value.output_format = skan::output::OutputFormat::Json;
    return value;
}

} // namespace

int main()
{
    auto pending = std::make_shared<std::vector<InjectedPortTransport::Pending>>();
    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.port_transport = [pending](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &) {
        return std::make_unique<InjectedPortTransport>(pending);
    };
    dependencies.after_port_submit = [pending](skan::portscan::PortScanScheduler &scheduler) {
        InjectedPortTransport injector(pending);
        injector.flush(scheduler);
    };
    std::vector<skan::orchestrator::ScanEventType> events;
    skan::orchestrator::ScanPipeline pipeline(config(), [&](const skan::orchestrator::ScanEvent &event) {
        events.push_back(event.type);
    }, std::move(dependencies));
    std::ostringstream output;
    assert(pipeline.run(output) == skan::core::StatusCode::Ok);
    assert(pipeline.state() == skan::orchestrator::PipelineState::Completed);
    assert(pipeline.report().has_value());
    const auto summary = skan::output::calculate_summary(*pipeline.report());
    assert(summary.hosts == 2U);
    assert(summary.open_ports == 4U);
    assert(!events.empty());
    assert(events.front() == skan::orchestrator::ScanEventType::ScanStarted);
    assert(events.back() == skan::orchestrator::ScanEventType::ScanCompleted);
    assert(output.str().find("\"hosts\"") != std::string::npos);

    skan::orchestrator::ScanPipeline cancelled(config());
    cancelled.cancel();
    std::ostringstream partial;
    assert(cancelled.run(partial) == skan::core::StatusCode::Ok);
    assert(cancelled.state() == skan::orchestrator::PipelineState::Cancelled);
    assert(cancelled.report().has_value());
    assert(partial.str().find("\"hosts\"") != std::string::npos);
    return 0;
}
