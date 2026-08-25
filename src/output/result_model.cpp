#include "output/result_model.hpp"

#include <cmath>
#include <limits>

namespace skan::output {

const char *output_format_name(OutputFormat format) noexcept
{
    switch (format) {
    case OutputFormat::Normal:
        return "normal";
    case OutputFormat::Json:
        return "json";
    case OutputFormat::Xml:
        return "xml";
    case OutputFormat::Grepable:
        return "grepable";
    }
    return "normal";
}

const char *output_status_name(OutputStatus status) noexcept
{
    switch (status) {
    case OutputStatus::Ok:
        return "ok";
    case OutputStatus::InvalidFormat:
        return "invalid-format";
    case OutputStatus::InvalidReport:
        return "invalid-report";
    case OutputStatus::IoError:
        return "io-error";
    case OutputStatus::SerializationError:
        return "serialization-error";
    }
    return "serialization-error";
}

OutputStatus parse_output_format(std::string_view text, OutputFormat &format) noexcept
{
    if (text == "normal") {
        format = OutputFormat::Normal;
    } else if (text == "json") {
        format = OutputFormat::Json;
    } else if (text == "xml") {
        format = OutputFormat::Xml;
    } else if (text == "grepable") {
        format = OutputFormat::Grepable;
    } else {
        return OutputStatus::InvalidFormat;
    }
    return OutputStatus::Ok;
}

ScanSummary calculate_summary(const ScanReport &report) noexcept
{
    ScanSummary summary;
    summary.hosts = report.hosts.size();
    for (const HostResult &host : report.hosts) {
        switch (host.state) {
        case discovery::HostState::Up:
            ++summary.hosts_up;
            break;
        case discovery::HostState::Down:
            ++summary.hosts_down;
            break;
        case discovery::HostState::Unknown:
            ++summary.hosts_unknown;
            break;
        }
        summary.ports_scanned += host.ports.size();
        for (const portscan::PortResult &port : host.ports) {
            switch (port.state) {
            case portscan::PortState::Open:
                ++summary.open_ports;
                break;
            case portscan::PortState::Closed:
                ++summary.closed_ports;
                break;
            case portscan::PortState::Filtered:
                ++summary.filtered_ports;
                break;
            case portscan::PortState::Unknown:
                ++summary.unknown_ports;
                break;
            case portscan::PortState::OpenOrFiltered:
                ++summary.open_or_filtered_ports;
                break;
            case portscan::PortState::Unfiltered:
                ++summary.unfiltered_ports;
                break;
            case portscan::PortState::Error:
                ++summary.error_ports;
                break;
            }
        }
        for (const detect::ServiceResult &service : host.services) {
            if (service.state == detect::DetectionState::Detected) {
                ++summary.services_detected;
            }
        }
        summary.os_matches += host.os_matches.size();
    }
    return summary;
}

namespace {

bool valid_nonnegative(double value) noexcept
{
    return std::isfinite(value) && value >= 0.0;
}

bool valid_confidence(double value) noexcept
{
    return std::isfinite(value) && value >= 0.0 && value <= 1.0;
}

} // namespace

OutputStatus validate_report(const ScanReport &report) noexcept
{
    if (report.scanner_name.empty() || report.scanner_version.empty()) {
        return OutputStatus::InvalidReport;
    }
    if (report.duration_ms.has_value() && !valid_nonnegative(*report.duration_ms)) {
        return OutputStatus::InvalidReport;
    }
    for (const HostResult &host : report.hosts) {
        if (host.address.empty()) {
            return OutputStatus::InvalidReport;
        }
        if (host.rtt_ms.has_value() && !valid_nonnegative(*host.rtt_ms)) {
            return OutputStatus::InvalidReport;
        }
        for (const portscan::PortResult &port : host.ports) {
            if (port.port.number == 0U || port.target.empty()) {
                return OutputStatus::InvalidReport;
            }
            if (port.rtt_ms.has_value() && !valid_nonnegative(*port.rtt_ms)) {
                return OutputStatus::InvalidReport;
            }
        }
        for (const detect::ServiceResult &service : host.services) {
            if (service.port.number == 0U || service.target.empty() || !valid_confidence(service.confidence)) {
                return OutputStatus::InvalidReport;
            }
            if (service.rtt_ms.has_value() && !valid_nonnegative(*service.rtt_ms)) {
                return OutputStatus::InvalidReport;
            }
        }
        for (const osdetect::OSMatchResult &match : host.os_matches) {
            if (match.fingerprint_name.empty() || !valid_confidence(match.confidence)) {
                return OutputStatus::InvalidReport;
            }
        }
    }
    if (report.timing_metrics.has_value()) {
        const scanengine::ScanMetrics &metrics = *report.timing_metrics;
        if (metrics.rtt_samples > 0U && !valid_nonnegative(metrics.average_rtt_ms)) {
            return OutputStatus::InvalidReport;
        }
        if (metrics.minimum_rtt_ms.has_value() && !valid_nonnegative(*metrics.minimum_rtt_ms)) {
            return OutputStatus::InvalidReport;
        }
        if (metrics.maximum_rtt_ms.has_value() && !valid_nonnegative(*metrics.maximum_rtt_ms)) {
            return OutputStatus::InvalidReport;
        }
        if (!valid_nonnegative(metrics.estimated_drop_rate) || metrics.estimated_drop_rate > 1.0) {
            return OutputStatus::InvalidReport;
        }
    }
    return OutputStatus::Ok;
}

} // namespace skan::output
