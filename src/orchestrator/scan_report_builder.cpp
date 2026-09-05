#include "orchestrator/scan_report_builder.hpp"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <utility>

namespace skan::orchestrator {
namespace {

discovery::HostState discovery_state_for(
    std::string_view address,
    std::span<const discovery::DiscoveryResult> results)
{
    bool saw_down = false;
    bool saw_unreachable = false;
    for (const discovery::DiscoveryResult &result : results) {
        if (result.target != address) {
            continue;
        }
        if (result.state == discovery::HostState::Up) {
            return discovery::HostState::Up;
        }
        saw_down = saw_down || result.state == discovery::HostState::Down;
        saw_unreachable = saw_unreachable || result.state == discovery::HostState::Unreachable;
    }
    if (saw_down) {
        return discovery::HostState::Down;
    }
    return saw_unreachable ? discovery::HostState::Unreachable : discovery::HostState::Unknown;
}

core::AddressFamily family_for(std::string_view address, const core::IpAddress &typed_address = {}) noexcept
{
    if (typed_address.valid()) {
        return typed_address.family;
    }
    return address.find(':') == std::string_view::npos ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
}

std::optional<double> rtt_for(std::string_view address, std::span<const discovery::DiscoveryResult> results)
{
    std::optional<double> best;
    for (const discovery::DiscoveryResult &result : results) {
        if (result.target != address || !result.rtt_ms.has_value()) {
            continue;
        }
        if (!best.has_value() || *result.rtt_ms < *best) {
            best = result.rtt_ms;
        }
    }
    return best;
}

bool port_state_proves_reachability(portscan::PortState state) noexcept
{
    return state == portscan::PortState::Open || state == portscan::PortState::Closed ||
           state == portscan::PortState::Unfiltered;
}

bool has_port_reachability_evidence(const output::HostResult &host) noexcept
{
    return std::any_of(host.ports.begin(), host.ports.end(), [](const portscan::PortResult &port) {
        return port_state_proves_reachability(port.state);
    });
}

} // namespace

output::ScanReport ScanReportBuilder::build(
    const ScanConfig &config,
    const core::Target &target,
    std::span<const discovery::DiscoveryResult> discovery_results,
    std::span<const portscan::PortResult> port_results,
    std::span<const detect::ServiceResult> service_results,
    std::span<const OSReportEvidence> os_results,
    const std::optional<scanengine::ScanMetrics> &timing_metrics,
    std::chrono::steady_clock::time_point started_at,
    std::chrono::steady_clock::time_point finished_at,
    std::span<const std::string> warnings,
    std::span<const std::string> errors)
{
    output::ScanReport report;
    report.target_spec = target.original_specification;
    if (config.adaptive_timing) {
        report.timing_profile = config.timing_profile.id;
    }
    report.timing_metrics = timing_metrics;
    const auto duration = std::chrono::duration<double, std::milli>(finished_at - started_at).count();
    report.duration_ms = duration < 0.0 ? 0.0 : duration;
    report.warnings.assign(warnings.begin(), warnings.end());
    report.errors.assign(errors.begin(), errors.end());

    std::unordered_map<std::string, std::size_t> host_indices;
    host_indices.reserve(target.resolved_hosts.size());
    report.hosts.reserve(target.resolved_hosts.size());
    for (const core::Host &host : target.resolved_hosts) {
        if (host_indices.contains(host.address)) {
            continue;
        }
        output::HostResult result;
        result.address = host.address;
        result.hostname = host.hostname;
        result.family = family_for(host.address, host.ip_address);
        if (config.discovery_enabled) {
            result.state = discovery_state_for(host.address, discovery_results);
            result.rtt_ms = rtt_for(host.address, discovery_results);
        } else {
            result.state = host.is_up ? discovery::HostState::Up : discovery::HostState::Unknown;
        }
        host_indices.emplace(result.address, report.hosts.size());
        report.hosts.push_back(std::move(result));
    }

    const auto host_index = [&report, &host_indices](const std::string &address) -> std::size_t {
        const auto found = host_indices.find(address);
        if (found != host_indices.end()) {
            return found->second;
        }
        const std::size_t index = report.hosts.size();
        output::HostResult created;
        created.address = address;
        created.family = family_for(address);
        report.hosts.push_back(std::move(created));
        host_indices.emplace(address, index);
        return index;
    };

    for (const portscan::PortResult &port : port_results) {
        report.hosts[host_index(port.target)].ports.push_back(port);
    }
    for (const detect::ServiceResult &service : service_results) {
        report.hosts[host_index(service.target)].services.push_back(service);
    }
    for (const OSReportEvidence &os : os_results) {
        output::HostResult &host = report.hosts[host_index(os.target)];
        host.os_matches.insert(host.os_matches.end(), os.matches.begin(), os.matches.end());
        if (os.result.has_value()) {
            host.os_detection = os.result;
        }
    }

    std::sort(report.hosts.begin(), report.hosts.end(), [](const output::HostResult &left, const output::HostResult &right) {
        return left.address < right.address;
    });
    for (output::HostResult &host : report.hosts) {
        if (has_port_reachability_evidence(host)) {
            host.state = discovery::HostState::Up;
        }
        std::sort(host.ports.begin(), host.ports.end(), [](const portscan::PortResult &left, const portscan::PortResult &right) {
            if (left.port.number != right.port.number) {
                return left.port.number < right.port.number;
            }
            return static_cast<unsigned int>(left.port.protocol) < static_cast<unsigned int>(right.port.protocol);
        });
        std::sort(host.services.begin(), host.services.end(), [](const detect::ServiceResult &left, const detect::ServiceResult &right) {
            return left.port.number < right.port.number;
        });
        std::sort(host.os_matches.begin(), host.os_matches.end(), [](const osdetect::OSMatchResult &left, const osdetect::OSMatchResult &right) {
            if (left.confidence != right.confidence) {
                return left.confidence > right.confidence;
            }
            if (left.specificity != right.specificity) {
                return left.specificity > right.specificity;
            }
            if (left.fingerprint_name != right.fingerprint_name) {
                return left.fingerprint_name < right.fingerprint_name;
            }
            return left.fingerprint_id < right.fingerprint_id;
        });
    }
    return report;
}

} // namespace skan::orchestrator