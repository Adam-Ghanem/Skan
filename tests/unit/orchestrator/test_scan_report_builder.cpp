#include <cassert>
#include <vector>

#include "orchestrator/scan_report_builder.hpp"

int main()
{
    skan::orchestrator::ScanConfig config;
    config.discovery_enabled = true;
    config.targets = {{"targets", {{"192.0.2.2", std::nullopt, false}, {"192.0.2.1", std::nullopt, false}}}};
    skan::core::Target target = config.targets.front();

    skan::discovery::DiscoveryResult up;
    up.target = "192.0.2.1";
    up.state = skan::discovery::HostState::Up;
    up.responded = true;
    up.rtt_ms = 2.5;
    up.reason = skan::discovery::DiscoveryReason::IcmpEchoReply;
    skan::discovery::DiscoveryResult unknown;
    unknown.target = "192.0.2.2";
    unknown.state = skan::discovery::HostState::Unknown;
    unknown.reason = skan::discovery::DiscoveryReason::Timeout;

    skan::portscan::PortResult port;
    port.target = "192.0.2.1";
    port.port = {22U, skan::portscan::Protocol::Tcp};
    port.state = skan::portscan::PortState::Open;
    port.probe = skan::portscan::ScanProbeType::TcpConnect;
    port.reason = skan::portscan::ScanReason::ImmediateSuccess;
    port.rtt_ms = 1.0;

    skan::osdetect::OSMatchResult os;
    os.fingerprint_name = "Synthetic OS";
    os.confidence = 0.9;
    skan::orchestrator::OSReportEvidence evidence{"192.0.2.1", {os}};
    const std::vector<std::string> warnings{"OS unavailable"};
    const std::vector<skan::discovery::DiscoveryResult> discovery_results{up, unknown};
    const std::vector<skan::portscan::PortResult> port_results{port};
    const std::vector<skan::orchestrator::OSReportEvidence> os_results{evidence};
    const auto report = skan::orchestrator::ScanReportBuilder::build(
        config, target, discovery_results, port_results, {}, os_results, std::nullopt,
        std::chrono::steady_clock::now(), std::chrono::steady_clock::now(), warnings, {});
    assert(report.hosts.size() == 2U);
    assert(report.hosts[0].address == "192.0.2.1");
    assert(report.hosts[0].state == skan::discovery::HostState::Up);
    assert(report.hosts[0].rtt_ms.has_value());
    assert(report.hosts[0].ports.size() == 1U);
    assert(report.hosts[0].os_matches.size() == 1U);
    assert(report.hosts[1].state == skan::discovery::HostState::Unknown);
    assert(report.warnings.size() == 1U);
    const skan::output::ScanSummary summary = skan::output::calculate_summary(report);
    assert(summary.hosts == 2U);
    assert(summary.hosts_up == 1U);
    assert(summary.hosts_unknown == 1U);
    assert(summary.open_ports == 1U);
    assert(summary.os_matches == 1U);
    return 0;
}
