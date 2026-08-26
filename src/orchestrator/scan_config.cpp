#include "orchestrator/scan_config.hpp"

namespace skan::orchestrator {
namespace {

bool valid_host_address(const core::Host &host) noexcept
{
    return host.ip_address.valid() || core::parse_ip_address(host.address).has_value();
}

} // namespace

const char *scan_transport_name(ScanTransport transport) noexcept
{
    switch (transport) {
    case ScanTransport::Offline:
        return "offline";
    case ScanTransport::Linux:
        return "linux";
    case ScanTransport::Connect:
        return "connect";
    }
    return "unknown";
}

const char *stage_kind_name(StageKind stage) noexcept
{
    switch (stage) {
    case StageKind::Discovery:
        return "discovery";
    case StageKind::PortScan:
        return "port-scan";
    case StageKind::UdpScan:
        return "udp-scan";
    case StageKind::ServiceDetection:
        return "service-detection";
    case StageKind::OSDetection:
        return "os-detection";
    case StageKind::Output:
        return "output";
    }
    return "unknown";
}

core::StatusCode ScanConfig::validate() const noexcept
{
    if (targets.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    if (min_parallelism == 0U || max_parallelism == 0U || min_parallelism > max_parallelism) {
        return core::StatusCode::InvalidArgument;
    }
    if (timeout.count() <= 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (timing_profile.validate() != core::StatusCode::Ok) {
        return core::StatusCode::InvalidArgument;
    }
    if (discovery_enabled && transport == ScanTransport::Connect) {
        return core::StatusCode::InvalidArgument;
    }
    if (udp_enabled && transport == ScanTransport::Connect) {
        return core::StatusCode::InvalidArgument;
    }
    if (max_response_bytes == 0U || max_probes_per_port == 0U || udp_timeout.count() <= 0 ||
        udp_max_outstanding == 0U) {
        return core::StatusCode::InvalidArgument;
    }
    if (transport != ScanTransport::Linux && interface_name.has_value()) {
        return core::StatusCode::InvalidArgument;
    }
    if (port_scan_enabled && transport == ScanTransport::Linux && port_method != portscan::ScanProbeType::TcpSyn) {
        return core::StatusCode::InvalidArgument;
    }
    if (port_scan_enabled && transport == ScanTransport::Connect && port_method != portscan::ScanProbeType::TcpConnect) {
        return core::StatusCode::InvalidArgument;
    }
    if (output_file.has_value() && output_file->empty()) {
        return core::StatusCode::InvalidArgument;
    }
    for (const core::Target &target : targets) {
        if (target.resolved_hosts.empty()) {
            return core::StatusCode::InvalidArgument;
        }
        for (const core::Host &host : target.resolved_hosts) {
            if (!valid_host_address(host)) {
                return core::StatusCode::InvalidArgument;
            }
        }
    }
    for (const std::uint16_t port : ports) {
        if (port == 0U) {
            return core::StatusCode::InvalidArgument;
        }
    }
    for (const std::uint16_t port : udp_ports) {
        if (port == 0U) {
            return core::StatusCode::InvalidArgument;
        }
    }
    return core::StatusCode::Ok;
}

} // namespace skan::orchestrator
