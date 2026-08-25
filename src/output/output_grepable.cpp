#include "output/output_grepable.hpp"

#include <iomanip>
#include <ostream>
#include <string>
#include <vector>

namespace skan::output {

OutputFormat GrepableOutputWriter::format() const noexcept
{
    return OutputFormat::Grepable;
}

OutputStatus GrepableOutputWriter::write(
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context) const
{
    if (validate_report(report) != OutputStatus::Ok) {
        return OutputStatus::InvalidReport;
    }
    output << "Scan: scanner=\"" << detail::grep_escape(report.scanner_name)
           << "\" version=\"" << detail::grep_escape(report.scanner_version) << '"';
    if (report.target_spec.has_value()) {
        output << " target=\"" << detail::grep_escape(*report.target_spec) << '"';
    }
    if (report.duration_ms.has_value()) {
        output << " duration_ms=" << std::setprecision(15) << *report.duration_ms;
    }
    output << '\n';
    for (const HostResult *host : detail::ordered_hosts(report)) {
        output << "Host: address=\"" << detail::grep_escape(host->address)
               << "\" state=" << discovery::host_state_name(host->state);
        if (context.include_hostnames && host->hostname.has_value()) {
            output << " hostname=\"" << detail::grep_escape(*host->hostname) << '"';
        }
        if (host->rtt_ms.has_value()) {
            output << " rtt_ms=" << std::setprecision(15) << *host->rtt_ms;
        }
        output << '\n';
        const std::vector<portscan::PortResult> ports = detail::ordered_ports(*host, context);
        const std::vector<detect::ServiceResult> services = detail::ordered_services(*host);
        for (const portscan::PortResult &port : ports) {
            output << "Port: target=\"" << detail::grep_escape(port.target)
                   << "\" number=" << port.port.number
                   << " protocol=" << portscan::protocol_name(port.port.protocol)
                   << " state=" << portscan::port_state_name(port.state)
                   << " probe=" << portscan::scan_probe_type_name(port.probe)
                   << " reason=" << portscan::scan_reason_name(port.reason);
            if (port.rtt_ms.has_value()) {
                output << " rtt_ms=" << std::setprecision(15) << *port.rtt_ms;
            }
            output << '\n';
            for (const detect::ServiceResult &service : services) {
                if (service.port.number != port.port.number || service.protocol != port.port.protocol) {
                    continue;
                }
                output << "Service: target=\"" << detail::grep_escape(service.target)
                       << "\" number=" << service.port.number
                       << " protocol=" << portscan::protocol_name(service.protocol)
                       << " state=" << detect::detection_state_name(service.state)
                       << " port_state=" << portscan::port_state_name(service.port_state);
                if (!service.service.empty()) {
                    output << " name=\"" << detail::grep_escape(service.service) << '"';
                }
                if (!service.product.empty()) {
                    output << " product=\"" << detail::grep_escape(service.product) << '"';
                }
                if (!service.version.empty()) {
                    output << " version=\"" << detail::grep_escape(service.version) << '"';
                }
                if (!service.extra.empty()) {
                    output << " extra=\"" << detail::grep_escape(service.extra) << '"';
                }
                output << " confidence=" << std::setprecision(15) << service.confidence
                       << " method=" << detect::detection_method_name(service.method)
                       << " error=" << detect::detection_error_name(service.error) << '\n';
            }
        }
        for (const osdetect::OSMatchResult &match : detail::ordered_os_matches(*host)) {
            output << "OS: address=\"" << detail::grep_escape(host->address)
                   << "\" name=\"" << detail::grep_escape(match.fingerprint_name)
                   << "\" confidence=" << std::setprecision(15) << match.confidence
                   << " class=" << db::match_category_name(match.category) << '\n';
        }
        for (const std::string &warning : host->warnings) {
            output << "Warning: address=\"" << detail::grep_escape(host->address)
                   << "\" message=\"" << detail::grep_escape(warning) << "\"\n";
        }
        for (const std::string &error : host->errors) {
            output << "Error: address=\"" << detail::grep_escape(host->address)
                   << "\" message=\"" << detail::grep_escape(error) << "\"\n";
        }
    }
    const ScanSummary summary = calculate_summary(report);
    output << "Summary: hosts=" << summary.hosts
           << " hosts_up=" << summary.hosts_up
           << " hosts_down=" << summary.hosts_down
           << " hosts_unknown=" << summary.hosts_unknown
           << " ports_scanned=" << summary.ports_scanned
           << " open_ports=" << summary.open_ports
           << " closed_ports=" << summary.closed_ports
           << " filtered_ports=" << summary.filtered_ports
           << " unknown_ports=" << summary.unknown_ports
           << " services_detected=" << summary.services_detected
           << " os_matches=" << summary.os_matches << '\n';
    for (const std::string &warning : report.warnings) {
        output << "Warning: scope=scan message=\"" << detail::grep_escape(warning) << "\"\n";
    }
    for (const std::string &error : report.errors) {
        output << "Error: scope=scan message=\"" << detail::grep_escape(error) << "\"\n";
    }
    return detail::check_stream(output);
}

} // namespace skan::output
