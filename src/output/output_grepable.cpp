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
    if (report.timing_metrics.has_value()) {
        const scanengine::ScanMetrics &metrics = *report.timing_metrics;
        output << "Metrics: targets_total=" << metrics.targets_total
               << " targets_completed=" << metrics.targets_completed
               << " targets_failed=" << metrics.targets_failed
               << " probes_submitted=" << metrics.probes_submitted
               << " probes_completed=" << metrics.probes_completed
               << " probes_timed_out=" << metrics.probes_timed_out
               << " probes_cancelled=" << metrics.probes_cancelled
               << " probes_retried=" << metrics.probes_retried
               << " duplicate_responses=" << metrics.duplicate_responses
               << " late_responses=" << metrics.late_responses
               << " malformed_responses=" << metrics.malformed_responses
               << " bytes_sent=" << metrics.bytes_sent
               << " bytes_received=" << metrics.bytes_received
               << " active_probes=" << metrics.active_probes
               << " peak_active_probes=" << metrics.peak_active_probes
               << " timeout_backoffs=" << metrics.timeout_backoffs << '\n';
    }
    for (const HostResult *host : detail::ordered_hosts(report)) {
        output << "Host: address=\"" << detail::grep_escape(host->address)
               << "\" family=" << core::address_family_name(host->family)
               << " state=" << discovery::host_state_name(host->state);
        if (context.include_hostnames && host->hostname.has_value()) {
            output << " hostname=\"" << detail::grep_escape(*host->hostname) << '"';
        }
        if (host->rtt_ms.has_value()) {
            output << " rtt_ms=" << std::setprecision(15) << *host->rtt_ms;
        }
        output << '\n';
        const std::vector<const portscan::PortResult *> ports = detail::ordered_ports(*host, context);
        const std::vector<const detect::ServiceResult *> services = detail::ordered_services(*host);
        for (const portscan::PortResult *port : ports) {
            output << "Port: target=\"" << detail::grep_escape(port->target)
                   << "\" number=" << port->port.number
                   << " protocol=" << portscan::protocol_name(port->port.protocol)
                   << " state=" << portscan::port_state_name(port->state)
                   << " probe=" << portscan::scan_probe_type_name(port->probe)
                   << " reason=" << portscan::scan_reason_name(port->reason);
            if (port->rtt_ms.has_value()) {
                output << " rtt_ms=" << std::setprecision(15) << *port->rtt_ms;
            }
            if (port->port.protocol == portscan::Protocol::Udp) {
                output << " probe_name=\"" << detail::grep_escape(port->probe_name.value_or("")) << '\"'
                       << " retry_count=" << port->retry_count;
            }
            output << '\n';
            for (const detect::ServiceResult *service : services) {
                if (service->port.number != port->port.number || service->protocol != port->port.protocol) {
                    continue;
                }
                output << "Service: target=\"" << detail::grep_escape(service->target)
                       << "\" number=" << service->port.number
                       << " protocol=" << portscan::protocol_name(service->protocol)
                       << " state=" << detect::detection_state_name(service->state)
                       << " port_state=" << portscan::port_state_name(service->port_state);
                if (!service->service.empty()) {
                    output << " name=\"" << detail::grep_escape(service->service) << '\"';
                }
                if (!service->product.empty()) {
                    output << " product=\"" << detail::grep_escape(service->product) << '\"';
                }
                if (!service->version.empty()) {
                    output << " version=\"" << detail::grep_escape(service->version) << '\"';
                }
                if (!service->extra.empty()) {
                    output << " extra=\"" << detail::grep_escape(service->extra) << '\"';
                }
                if (!service->hostname.empty()) {
                    output << " hostname=\"" << detail::grep_escape(service->hostname) << '\"';
                }
                if (!service->tunnel.empty()) {
                    output << " tunnel=\"" << detail::grep_escape(service->tunnel) << '\"';
                }
                if (service->tls_detected) {
                    output << " tls=true";
                    if (!service->tls_version.empty())
                        output << " tls_version=\"" << detail::grep_escape(service->tls_version) << '\"';
                }
                output << " confidence=" << std::setprecision(15) << service->confidence
                       << " method=" << detect::detection_method_name(service->method)
                       << " error=" << detect::detection_error_name(service->error);
                if (!service->probe_name.empty()) {
                    output << " probe=\"" << detail::grep_escape(service->probe_name) << '"';
                }
                if (service->rtt_ms.has_value()) {
                    output << " rtt_ms=" << std::setprecision(15) << *service->rtt_ms;
                }
                output << '\n';
            }
        }
        if (host->os_detection.has_value()) {
            const osdetect::OSDetectionResult &detection = *host->os_detection;
            output << "OSStatus: address=\"" << detail::grep_escape(host->address)
                   << "\" family=" << core::address_family_name(detection.address_family)
                   << " state=" << osdetect::os_detection_state_name(detection.state)
                   << " error=" << osdetect::os_detection_error_name(detection.error)
                   << " confidence=" << std::setprecision(15) << detection.confidence
                   << " probes=" << detection.probes_sent
                   << " responses=" << detection.responses_received
                   << " timeouts=" << detection.probes_timed_out
                   << " tcp_evidence=" << detection.observed.tcp_observations.size()
                   << " icmp_evidence=" << detection.observed.icmp_observations.size()
                   << " udp_evidence=" << detection.observed.udp_observations.size();
            if (!detection.fingerprint_id.empty()) {
                output << " fingerprint_id=\"" << detail::grep_escape(detection.fingerprint_id) << '"';
            }
            if (detection.rtt_ms.has_value()) {
                output << " rtt_ms=" << std::setprecision(15) << *detection.rtt_ms;
            }
            output << '\n';
        }
        for (const osdetect::OSMatchResult *match : detail::ordered_os_matches(*host)) {
            output << "OS: address=\"" << detail::grep_escape(host->address)
                   << "\" name=\"" << detail::grep_escape(match->fingerprint_name)
                   << "\" id=\"" << detail::grep_escape(match->fingerprint_id)
                   << "\" confidence=" << std::setprecision(15) << match->confidence
                   << " class=" << db::match_category_name(match->category);
            if (!match->vendor.empty()) {
                output << " vendor=\"" << detail::grep_escape(match->vendor) << '"';
            }
            if (!match->family.empty()) {
                output << " family=\"" << detail::grep_escape(match->family) << '"';
            }
            output << '\n';
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
           << " hosts_unreachable=" << summary.hosts_unreachable
           << " ports_scanned=" << summary.ports_scanned
           << " open_ports=" << summary.open_ports
           << " closed_ports=" << summary.closed_ports
           << " filtered_ports=" << summary.filtered_ports
           << " open_or_filtered_ports=" << summary.open_or_filtered_ports
           << " unfiltered_ports=" << summary.unfiltered_ports
           << " error_ports=" << summary.error_ports
           << " unreachable_ports=" << summary.unreachable_ports
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
