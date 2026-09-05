#include <cassert>
#include <sstream>
#include <string>
#include <vector>

#include "orchestrator/scan_report_builder.hpp"
#include "output/output_json.hpp"

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
    skan::orchestrator::OSReportEvidence evidence{"192.0.2.1", {os}, std::nullopt};
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

    // With discovery disabled, transport-level responses become authoritative
    // reachability evidence. A refused TCP connection is still a response from
    // the target and must not produce "reachable" next to "0 up" in the final report.
    skan::orchestrator::ScanConfig no_discovery;
    no_discovery.discovery_enabled = false;
    no_discovery.targets = {{"198.51.100.10", {{"198.51.100.10", std::nullopt, false}}}};
    skan::core::Target no_discovery_target = no_discovery.targets.front();

    skan::portscan::PortResult refused;
    refused.target = "198.51.100.10";
    refused.port = {23U, skan::portscan::Protocol::Tcp};
    refused.state = skan::portscan::PortState::Closed;
    refused.probe = skan::portscan::ScanProbeType::TcpConnect;
    refused.reason = skan::portscan::ScanReason::ConnectionRefused;
    refused.rtt_ms = 1.5;
    const std::vector<skan::portscan::PortResult> refused_results{refused};

    const auto transport_proven_report = skan::orchestrator::ScanReportBuilder::build(
        no_discovery, no_discovery_target, {}, refused_results, {}, {}, std::nullopt,
        std::chrono::steady_clock::now(), std::chrono::steady_clock::now(), {}, {});
    assert(transport_proven_report.hosts.size() == 1U);
    assert(transport_proven_report.hosts[0].state == skan::discovery::HostState::Up);
    assert(transport_proven_report.hosts[0].ports.size() == 1U);
    const skan::output::ScanSummary transport_proven_summary =
        skan::output::calculate_summary(transport_proven_report);
    assert(transport_proven_summary.hosts == 1U);
    assert(transport_proven_summary.hosts_up == 1U);
    assert(transport_proven_summary.hosts_unknown == 0U);
    assert(transport_proven_summary.closed_ports == 1U);

    skan::output::JsonOutputWriter json_writer;
    std::ostringstream json_output;
    assert(json_writer.write(transport_proven_report, json_output, skan::output::OutputContext{}) ==
           skan::output::OutputStatus::Ok);
    const std::string json = json_output.str();
    assert(json.find("\"state\": \"up\"") != std::string::npos);
    assert(json.find("\"hosts_up\": 1") != std::string::npos);
    assert(json.find("\"hosts_unknown\": 0") != std::string::npos);

    // Silence/timeout evidence is not enough to claim a host is reachable.
    skan::portscan::PortResult filtered = refused;
    filtered.target = "198.51.100.11";
    filtered.state = skan::portscan::PortState::Filtered;
    filtered.reason = skan::portscan::ScanReason::Timeout;
    filtered.rtt_ms.reset();
    skan::orchestrator::ScanConfig uncertain_config;
    uncertain_config.discovery_enabled = false;
    uncertain_config.targets = {{"198.51.100.11", {{"198.51.100.11", std::nullopt, false}}}};
    const std::vector<skan::portscan::PortResult> filtered_results{filtered};
    const auto uncertain_report = skan::orchestrator::ScanReportBuilder::build(
        uncertain_config, uncertain_config.targets.front(), {}, filtered_results, {}, {}, std::nullopt,
        std::chrono::steady_clock::now(), std::chrono::steady_clock::now(), {}, {});
    assert(uncertain_report.hosts.size() == 1U);
    assert(uncertain_report.hosts[0].state == skan::discovery::HostState::Unknown);
    const skan::output::ScanSummary uncertain_summary = skan::output::calculate_summary(uncertain_report);
    assert(uncertain_summary.hosts_up == 0U);
    assert(uncertain_summary.hosts_unknown == 1U);
    assert(uncertain_summary.filtered_ports == 1U);
    return 0;
}
