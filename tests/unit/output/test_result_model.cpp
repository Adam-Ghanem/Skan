#include <cassert>
#include <cmath>
#include <limits>

#include "output/result_model.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::ScanReport empty;
    assert(empty.hosts.empty());
    assert(!empty.target_spec.has_value());
    const skan::output::ScanSummary empty_summary = skan::output::calculate_summary(empty);
    assert(empty_summary.hosts == 0U);
    assert(empty_summary.ports_scanned == 0U);
    assert(skan::output::validate_report(empty) == skan::output::OutputStatus::Ok);

    const skan::output::ScanReport report = skan::output::test::make_report();
    const skan::output::ScanSummary summary = skan::output::calculate_summary(report);
    assert(summary.hosts == 2U);
    assert(summary.hosts_up == 1U);
    assert(summary.hosts_unknown == 1U);
    assert(summary.ports_scanned == 4U);
    assert(summary.open_ports == 1U);
    assert(summary.closed_ports == 1U);
    assert(summary.filtered_ports == 1U);
    assert(summary.unreachable_ports == 1U);
    assert(summary.services_detected == 1U);
    assert(summary.os_matches == 2U);
    assert(summary.hosts_unreachable == 0U);
    assert(skan::output::validate_report(report) == skan::output::OutputStatus::Ok);

    skan::output::ScanReport unreachable_report;
    skan::output::HostResult unreachable_host;
    unreachable_host.address = "192.0.2.30";
    unreachable_host.state = skan::discovery::HostState::Unreachable;
    unreachable_report.hosts.push_back(std::move(unreachable_host));
    assert(skan::output::calculate_summary(unreachable_report).hosts_unreachable == 1U);

    skan::output::ScanReport invalid = report;
    invalid.hosts.front().address.clear();
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.hosts.front().services.front().confidence = std::numeric_limits<double>::infinity();
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.duration_ms = -1.0;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.timing_metrics->estimated_drop_rate = 2.0;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);

    skan::output::ScanReport states_report;
    skan::output::HostResult states_host;
    states_host.address = "192.0.2.40";
    states_host.state = skan::discovery::HostState::Up;
    const auto add_port = [&](std::uint16_t number, skan::portscan::Protocol protocol,
                              skan::portscan::ScanProbeType probe, skan::portscan::PortState state,
                              skan::portscan::ScanReason reason) {
        skan::portscan::PortResult result;
        result.target = states_host.address;
        result.port = {number, protocol};
        result.probe = probe;
        result.state = state;
        result.reason = reason;
        states_host.ports.push_back(std::move(result));
    };
    add_port(1001U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpSyn,
             skan::portscan::PortState::Open, skan::portscan::ScanReason::SynAck);
    add_port(1002U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpSyn,
             skan::portscan::PortState::Closed, skan::portscan::ScanReason::Rst);
    add_port(1003U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpSyn,
             skan::portscan::PortState::Filtered, skan::portscan::ScanReason::Timeout);
    add_port(1004U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpSyn,
             skan::portscan::PortState::Unknown, skan::portscan::ScanReason::ConflictingEvidence);
    add_port(1005U, skan::portscan::Protocol::Udp, skan::portscan::ScanProbeType::Udp,
             skan::portscan::PortState::OpenOrFiltered, skan::portscan::ScanReason::UdpTimeout);
    add_port(1006U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpAck,
             skan::portscan::PortState::Unfiltered, skan::portscan::ScanReason::AckRst);
    add_port(1007U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpConnect,
             skan::portscan::PortState::Error, skan::portscan::ScanReason::SocketError);
    add_port(1008U, skan::portscan::Protocol::Tcp, skan::portscan::ScanProbeType::TcpConnect,
             skan::portscan::PortState::Unreachable, skan::portscan::ScanReason::NetworkUnreachable);
    states_report.hosts.push_back(std::move(states_host));

    assert(skan::output::validate_report(states_report) == skan::output::OutputStatus::Ok);
    const skan::output::ScanSummary states = skan::output::calculate_summary(states_report);
    assert(states.ports_scanned == 8U);
    assert(states.open_ports == 1U);
    assert(states.closed_ports == 1U);
    assert(states.filtered_ports == 1U);
    assert(states.unknown_ports == 1U);
    assert(states.open_or_filtered_ports == 1U);
    assert(states.unfiltered_ports == 1U);
    assert(states.error_ports == 1U);
    assert(states.unreachable_ports == 1U);
    assert(states.open_ports + states.closed_ports + states.filtered_ports + states.unknown_ports +
               states.open_or_filtered_ports + states.unfiltered_ports + states.error_ports +
               states.unreachable_ports ==
           states.ports_scanned);

    invalid = states_report;
    invalid.hosts.front().ports.front().reason = skan::portscan::ScanReason::Timeout;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = states_report;
    invalid.hosts.front().ports[4].state = skan::portscan::PortState::Open;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = states_report;
    invalid.hosts.front().ports[5].state = skan::portscan::PortState::Open;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    return 0;
}
