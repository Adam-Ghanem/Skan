#include "output/output_normal.hpp"

#include <iomanip>
#include <ostream>
#include <string>

namespace skan::output {

OutputFormat NormalOutputWriter::format() const noexcept
{
    return OutputFormat::Normal;
}

OutputStatus NormalOutputWriter::write(
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context) const
{
    if (validate_report(report) != OutputStatus::Ok) {
        return OutputStatus::InvalidReport;
    }
    output << report.scanner_name << ' ' << report.scanner_version << '\n';
    output << "Scan report";
    if (report.target_spec.has_value()) {
        output << " for " << detail::grep_escape(*report.target_spec);
    }
    output << '\n';
    for (const HostResult *host : detail::ordered_hosts(report)) {
        output << "Host " << detail::grep_escape(host->address);
        if (context.include_hostnames && host->hostname.has_value()) {
            output << " (" << detail::grep_escape(*host->hostname) << ')';
        }
        output << " is " << discovery::host_state_name(host->state);
        if (host->rtt_ms.has_value()) {
            output << " rtt_ms=" << std::setprecision(15) << *host->rtt_ms;
        }
        output << '\n';
        const std::vector<detect::ServiceResult> services = detail::ordered_services(*host);
        const std::vector<portscan::PortResult> ports = detail::ordered_ports(*host, context);
        for (const portscan::PortResult &port : ports) {
            output << "  Port " << port.port.number << '/'
                   << portscan::protocol_name(port.port.protocol)
                   << " " << portscan::port_state_name(port.state);
            if (!port.rtt_ms.has_value()) {
                // No RTT field is printed when the source result did not provide one.
            } else {
                output << " rtt_ms=" << std::setprecision(15) << *port.rtt_ms;
            }
            for (const detect::ServiceResult &service : services) {
                if (service.port.number != port.port.number || service.protocol != port.port.protocol) {
                    continue;
                }
                if (service.state == detect::DetectionState::Detected) {
                    if (!service.service.empty()) {
                        output << " service=" << detail::grep_escape(service.service);
                    }
                    if (!service.product.empty()) {
                        output << " product=" << detail::grep_escape(service.product);
                    }
                    if (!service.version.empty()) {
                        output << " version=" << detail::grep_escape(service.version);
                    }
                    output << " confidence=" << std::setprecision(15) << service.confidence;
                }
            }
            output << '\n';
        }
        if (!host->os_matches.empty()) {
            output << "  OS detection:\n";
            for (const osdetect::OSMatchResult &match : detail::ordered_os_matches(*host)) {
                output << "    " << detail::grep_escape(match.fingerprint_name)
                       << " confidence=" << std::setprecision(15) << match.confidence
                       << " class=" << db::match_category_name(match.category) << '\n';
            }
        }
        for (const std::string &warning : host->warnings) {
            output << "  Warning: " << detail::grep_escape(warning) << '\n';
        }
        for (const std::string &error : host->errors) {
            output << "  Error: " << detail::grep_escape(error) << '\n';
        }
    }
    const ScanSummary summary = calculate_summary(report);
    output << "Summary: hosts=" << summary.hosts
           << " up=" << summary.hosts_up
           << " down=" << summary.hosts_down
           << " unknown=" << summary.hosts_unknown
           << " ports=" << summary.ports_scanned
           << " open=" << summary.open_ports
           << " closed=" << summary.closed_ports
           << " filtered=" << summary.filtered_ports
           << " services=" << summary.services_detected
           << " os_matches=" << summary.os_matches << '\n';
    if (report.duration_ms.has_value()) {
        output << "Scan completed in " << std::setprecision(15) << *report.duration_ms << "ms\n";
    }
    if (!report.warnings.empty()) {
        output << "Warnings:\n";
        for (const std::string &warning : report.warnings) {
            output << "  " << detail::grep_escape(warning) << '\n';
        }
    }
    if (!report.errors.empty()) {
        output << "Errors:\n";
        for (const std::string &error : report.errors) {
            output << "  " << detail::grep_escape(error) << '\n';
        }
    }
    return detail::check_stream(output);
}

} // namespace skan::output
