#include <cassert>
#include <sstream>
#include <vector>

#include "orchestrator/scan_pipeline.hpp"

int main()
{
    skan::orchestrator::ScanConfig config;
    config.targets = {{"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}}};
    config.transport = skan::orchestrator::ScanTransport::Offline;
    config.port_method = skan::portscan::ScanProbeType::TcpSyn;
    config.ports = {80U};
    config.timeout = std::chrono::milliseconds{1};
    config.output_format = skan::output::OutputFormat::Json;

    skan::orchestrator::ScanPipeline *pipeline = nullptr;
    std::vector<skan::orchestrator::ScanEventType> events;
    skan::orchestrator::ScanPipeline instance(config, [&](const skan::orchestrator::ScanEvent &event) {
        events.push_back(event.type);
        if (event.type == skan::orchestrator::ScanEventType::StageStarted && pipeline != nullptr) {
            pipeline->cancel();
        }
    });
    pipeline = &instance;
    std::ostringstream output;
    assert(instance.run(output) == skan::core::StatusCode::Ok);
    assert(instance.state() == skan::orchestrator::PipelineState::Cancelled);
    assert(instance.report().has_value());
    assert(output.str().find("\"hosts\"") != std::string::npos);
    assert(!events.empty());
    assert(events.back() == skan::orchestrator::ScanEventType::ScanCancelled);
    for (const auto type : events) {
        assert(type != skan::orchestrator::ScanEventType::StageCompleted);
        assert(type != skan::orchestrator::ScanEventType::ScanCompleted);
    }
    return 0;
}
