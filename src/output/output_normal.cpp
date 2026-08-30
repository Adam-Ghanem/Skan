#include "output/output_normal.hpp"

#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace skan::output {
namespace {

constexpr std::string_view kReset{"\x1b[0m"};
constexpr std::string_view kCyan{"\x1b[36m"};
constexpr std::string_view kGreen{"\x1b[32m"};
constexpr std::string_view kYellow{"\x1b[33m"};
constexpr std::string_view kRed{"\x1b[31m"};
constexpr std::string_view kBold{"\x1b[1m"};
constexpr std::string_view kDim{"\x1b[2m"};

std::string paint(std::string_view text, std::string_view color, const OutputContext &context)
{
    if (!context.color_enabled) {
        return std::string(text);
    }
    return std::string(color) + std::string(text) + std::string(kReset);
}

std::string state_text(portscan::PortState state, const OutputContext &context)
{
    const std::string_view name = portscan::port_state_name(state);
    switch (state) {
    case portscan::PortState::Open:
        return paint(name, kGreen, context);
    case portscan::PortState::Filtered:
    case portscan::PortState::OpenOrFiltered:
        return paint(name, kYellow, context);
    case portscan::PortState::Closed:
    case portscan::PortState::Error:
    case portscan::PortState::Unreachable:
        return paint(name, kRed, context);
    case portscan::PortState::Unfiltered:
    case portscan::PortState::Unknown:
        return paint(name, kDim, context);
    }
    return std::string(name);
}

std::string host_state_text(discovery::HostState state, const OutputContext &context)
{
    const std::string_view name = discovery::host_state_name(state);
    if (state == discovery::HostState::Up) {
        return paint(name, kGreen, context);
    }
    if (state == discovery::HostState::Down) {
        return paint(name, kRed, context);
    }
    return paint(name, kYellow, context);
}

const detect::ServiceResult *service_for(
    const std::vector<const detect::ServiceResult *> &services,
    const portscan::PortResult &port)
{
    for (const detect::ServiceResult *service : services) {
        if (service->port.number == port.port.number && service->protocol == port.port.protocol &&
            service->state == detect::DetectionState::Detected) {
            return service;
        }
    }
    return nullptr;
}

std::string service_label(const detect::ServiceResult *service)
{
    if (service == nullptr || service->service.empty()) {
        return "-";
    }
    return detail::grep_escape(service->service);
}

std::string version_label(const detect::ServiceResult *service)
{
    if (service == nullptr) {
        return "-";
    }
    std::string value;
    if (!service->product.empty()) {
        value = detail::grep_escape(service->product);
    }
    if (!service->version.empty()) {
        if (!value.empty()) {
            value.push_back(' ');
        }
        value += detail::grep_escape(service->version);
    }
    return value.empty() ? "-" : value;
}

void write_brand(std::ostream &output, const ScanReport &report, const OutputContext &context)
{
    const std::string brand = paint("◈ Skan", kCyan, context);
    const std::string subtitle = paint("Modern network reconnaissance engine", kDim, context);
    const std::string scanner_prefix = report.scanner_name + " ";
    const bool version_already_branded = report.scanner_version.rfind(scanner_prefix, 0U) == 0U;
    output << "╭─ " << brand << " ─────────────────────────────────────────────╮\n"
           << "│ " << subtitle << '\n'
           << "│ ";
    if (!version_already_branded) {
        output << 'v';
    }
    output << report.scanner_version << '\n'
           << "╰───────────────────────────────────────────────────────╯\n\n";
}

void write_service_details(
    std::ostream &output,
    const detect::ServiceResult &service,
    const OutputContext &context)
{
    output << "      " << paint("↳", kCyan, context)
           << " confidence=" << std::setprecision(15) << service.confidence
           << " method=" << detect::detection_method_name(service.method)
           << " error=" << detect::detection_error_name(service.error);
    if (!service.probe_name.empty()) {
        output << " probe=" << detail::grep_escape(service.probe_name);
    }
    if (!service.hostname.empty()) {
        output << " hostname=" << detail::grep_escape(service.hostname);
    }
    if (!service.tunnel.empty()) {
        output << " tunnel=" << detail::grep_escape(service.tunnel);
    }
    if (service.tls_detected) {
        output << " tls=yes";
        if (!service.tls_version.empty()) {
            output << " tls_version=" << detail::grep_escape(service.tls_version);
        }
    }
    if (service.rtt_ms.has_value()) {
        output << " rtt_ms=" << std::setprecision(15) << *service.rtt_ms;
    }
    output << '\n';
}

} // namespace

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

    write_brand(output, report, context);
    output << paint("Scan report", kBold, context);
    if (report.target_spec.has_value()) {
        output << " for " << paint(detail::grep_escape(*report.target_spec), kCyan, context);
    }
    output << "\n\n";

    for (const HostResult *host : detail::ordered_hosts(report)) {
        output << paint("→", kCyan, context) << " Host " << paint(detail::grep_escape(host->address), kCyan, context);
        if (host->family == core::AddressFamily::IPv6) {
            output << " [family=ipv6]";
        }
        if (context.include_hostnames && host->hostname.has_value()) {
            output << " (" << detail::grep_escape(*host->hostname) << ')';
        }
        output << " is " << host_state_text(host->state, context);
        if (host->rtt_ms.has_value()) {
            output << " · " << std::setprecision(15) << *host->rtt_ms << " ms";
        }
        output << '\n';

        const std::vector<const detect::ServiceResult *> services = detail::ordered_services(*host);
        const std::vector<const portscan::PortResult *> ports = detail::ordered_ports(*host, context);
        if (!ports.empty()) {
            output << "\n  " << paint("PORT", kCyan, context)
                   << std::string(8U, ' ') << paint("STATE", kCyan, context)
                   << std::string(7U, ' ') << paint("SERVICE", kCyan, context)
                   << std::string(7U, ' ') << paint("VERSION", kCyan, context) << '\n';
            output << "  ─────────────────────────────────────────────────────────────\n";
        }

        for (const portscan::PortResult *port : ports) {
            std::ostringstream endpoint;
            endpoint << port->port.number << '/' << portscan::protocol_name(port->port.protocol);
            const detect::ServiceResult *service = service_for(services, *port);
            const std::string raw_state = portscan::port_state_name(port->state);
            output << "  " << std::left << std::setw(12) << endpoint.str()
                   << state_text(port->state, context);
            if (raw_state.size() < 20U) {
                output << std::string(20U - raw_state.size(), ' ');
            }
            output << std::setw(14) << service_label(service)
                   << version_label(service) << std::right;
            if (port->rtt_ms.has_value()) {
                output << "  [" << std::setprecision(15) << *port->rtt_ms << " ms]";
            }
            if (port->port.protocol == portscan::Protocol::Udp) {
                output << "  probe=" << detail::grep_escape(port->probe_name.value_or(""))
                       << " retries=" << port->retry_count;
            }
            output << '\n';
            if (service != nullptr) {
                write_service_details(output, *service, context);
            }
        }

        if (host->os_detection.has_value()) {
            const osdetect::OSDetectionResult &detection = *host->os_detection;
            output << "\n  " << paint("OS", kCyan, context)
                   << " family=" << core::address_family_name(detection.address_family)
                   << " status=" << osdetect::os_detection_state_name(detection.state)
                   << " error=" << osdetect::os_detection_error_name(detection.error)
                   << " confidence=" << std::setprecision(15) << detection.confidence
                   << " probes=" << detection.probes_sent
                   << " responses=" << detection.responses_received
                   << " timeouts=" << detection.probes_timed_out
                   << " tcp_evidence=" << detection.observed.tcp_observations.size()
                   << " icmp_evidence=" << detection.observed.icmp_observations.size()
                   << " udp_evidence=" << detection.observed.udp_observations.size();
            if (!detection.fingerprint_id.empty()) {
                output << " fingerprint=" << detail::grep_escape(detection.fingerprint_id);
            }
            if (detection.rtt_ms.has_value()) {
                output << " rtt_ms=" << std::setprecision(15) << *detection.rtt_ms;
            }
            output << '\n';
        }
        if (!host->os_matches.empty()) {
            output << "  " << paint("OS detection", kCyan, context) << ":\n";
            for (const osdetect::OSMatchResult *match : detail::ordered_os_matches(*host)) {
                output << "    " << detail::grep_escape(match->fingerprint_name)
                       << " id=" << detail::grep_escape(match->fingerprint_id)
                       << " confidence=" << std::setprecision(15) << match->confidence
                       << " class=" << db::match_category_name(match->category)
                       << " vendor=" << detail::grep_escape(match->vendor)
                       << " family=" << detail::grep_escape(match->family) << '\n';
            }
        }
        for (const std::string &warning : host->warnings) {
            output << "  " << paint("! Warning:", kYellow, context) << ' ' << detail::grep_escape(warning) << '\n';
        }
        for (const std::string &error : host->errors) {
            output << "  " << paint("× Error:", kRed, context) << ' ' << detail::grep_escape(error) << '\n';
        }
        output << '\n';
    }

    const ScanSummary summary = calculate_summary(report);
    output << "───────────────────────────────────────────────────────────────\n";
    output << paint("✓ Scan complete", kGreen, context);
    if (report.duration_ms.has_value()) {
        output << " · " << std::setprecision(15) << *report.duration_ms << "ms";
    }
    output << '\n';
    output << "  " << paint(std::to_string(summary.open_ports) + " open", kGreen, context)
           << " · " << paint(std::to_string(summary.closed_ports) + " closed", kRed, context)
           << " · " << paint(std::to_string(summary.filtered_ports) + " filtered", kYellow, context)
           << " · " << summary.ports_scanned << " scanned\n";

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
    output << "Summary: hosts=" << summary.hosts
           << " up=" << summary.hosts_up
           << " down=" << summary.hosts_down
           << " unknown=" << summary.hosts_unknown
           << " unreachable_hosts=" << summary.hosts_unreachable
           << " ports=" << summary.ports_scanned
           << " open=" << summary.open_ports
           << " closed=" << summary.closed_ports
           << " filtered=" << summary.filtered_ports
           << " open_or_filtered=" << summary.open_or_filtered_ports
           << " unfiltered=" << summary.unfiltered_ports
           << " errors=" << summary.error_ports
           << " unreachable=" << summary.unreachable_ports
           << " services=" << summary.services_detected
           << " os_matches=" << summary.os_matches << '\n';
    if (!report.warnings.empty()) {
        output << paint("Warnings:", kYellow, context) << '\n';
        for (const std::string &warning : report.warnings) {
            output << "  " << detail::grep_escape(warning) << '\n';
        }
    }
    if (!report.errors.empty()) {
        output << paint("Errors:", kRed, context) << '\n';
        for (const std::string &error : report.errors) {
            output << "  " << detail::grep_escape(error) << '\n';
        }
    }
    output << '\n' << paint("Skan", kCyan, context) << " — See more. Know more. Secure more.\n";
    return detail::check_stream(output);
}

} // namespace skan::output
