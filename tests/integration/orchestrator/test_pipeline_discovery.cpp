#include <cassert>
#include <sstream>

#include "orchestrator/scan_pipeline.hpp"
#include "packet/icmp.hpp"

int main()
{
    skan::orchestrator::ScanConfig config;
    config.targets = {{"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}}};
    config.transport = skan::orchestrator::ScanTransport::Offline;
    config.discovery_enabled = true;
    config.port_scan_enabled = false;
    config.output_format = skan::output::OutputFormat::Json;
    config.timeout = std::chrono::milliseconds{1};

    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.after_discovery_submit = [](skan::discovery::Discovery &discovery) {
        skan::packet::ICMP reply(skan::packet::IcmpType::EchoReply);
        reply.set_identifier(0x534BU);
        reply.set_sequence(1U);
        reply.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
        (void)discovery.receive({1U, "127.0.0.1", reply.serialize(), skan::discovery::DiscoveryClock::now()});
    };
    skan::orchestrator::ScanPipeline pipeline(config, {}, std::move(dependencies));
    std::ostringstream output;
    assert(pipeline.run(output) == skan::core::StatusCode::Ok);
    assert(pipeline.state() == skan::orchestrator::PipelineState::Completed);
    assert(pipeline.report().has_value());
    assert(pipeline.report()->hosts.size() == 1U);
    assert(pipeline.report()->hosts.front().state == skan::discovery::HostState::Up);
    assert(output.str().find("\"state\": \"UP\"") != std::string::npos);
    return 0;
}
