#include <cassert>
#include <sstream>
#include <string>
#include <utility>

#include "orchestrator/scan_orchestrator.hpp"
#include "target/target_engine.hpp"

int main()
{
    using namespace skan;
    const target::TargetResolutionResult resolved = target::TargetEngine::resolve("192.0.2.0/30");
    assert(resolved.success());
    assert(resolved.target_set.size() == 4U);

    core::Target normalized;
    normalized.original_specification = "192.0.2.0/30";
    for (const target::ResolvedTarget &item : resolved.target_set.targets) {
        normalized.resolved_hosts.push_back(core::Host{
            target::format_ip_address(item.ip_address), item.source_hostname, false, item.ip_address});
    }

    orchestrator::ScanConfig config;
    config.targets.push_back(std::move(normalized));
    config.transport = orchestrator::ScanTransport::Offline;
    config.discovery_enabled = true;
    config.output_format = output::OutputFormat::Grepable;
    std::ostringstream output;
    orchestrator::ScanOrchestrator orchestrator(config);
    assert(orchestrator.run(output) == core::StatusCode::Ok);
    assert(orchestrator.report().has_value());
    const output::ScanSummary summary = output::calculate_summary(*orchestrator.report());
    assert(summary.hosts == 4U);
    assert(summary.hosts_unknown == 4U);
    assert(summary.ports_scanned == 0U);
    assert(output.str().find("hosts_unknown=4") != std::string::npos);

    const target::TargetResolutionResult mixed = target::TargetEngine::resolve("127.0.0.1,::1");
    assert(mixed.success());
    assert(mixed.target_set.size() == 2U);
    assert(mixed.target_set.targets[0].ip_address.is_ipv4());
    assert(mixed.target_set.targets[1].ip_address.is_ipv6());
    assert(target::format_ip_address(mixed.target_set.targets[1].ip_address) == "::1");
    return 0;
}
