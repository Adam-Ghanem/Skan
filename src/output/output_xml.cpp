#include "output/output_xml.hpp"

#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace skan::output {
namespace {

class XmlWriter final {
public:
    XmlWriter(std::ostream &output, bool pretty) : output_(output), pretty_(pretty) {}

    void element(std::size_t depth, std::string_view name, std::string_view value)
    {
        indent(depth);
        output_ << '<' << name << '>' << detail::xml_escape(value) << "</" << name << '>';
        newline();
    }

    void open(std::size_t depth, std::string_view name)
    {
        indent(depth);
        output_ << '<' << name << '>';
        newline();
    }

    void close(std::size_t depth, std::string_view name)
    {
        indent(depth);
        output_ << "</" << name << '>';
        newline();
    }

    void self_closing(std::size_t depth, std::string_view name, const std::string &attributes)
    {
        indent(depth);
        output_ << '<' << name << attributes << "/>";
        newline();
    }

    void raw(std::string_view value)
    {
        output_ << value;
    }

    void indent(std::size_t depth)
    {
        if (pretty_) {
            output_ << std::string(depth * 2U, ' ');
        }
    }

    void newline()
    {
        if (pretty_) {
            output_ << '\n';
        }
    }

private:
    std::ostream &output_;
    bool pretty_;
};

std::string attribute(std::string_view name, std::string_view value)
{
    return " " + std::string(name) + "=\"" + detail::xml_escape(value) + "\"";
}

std::string attribute_number(std::string_view name, double value)
{
    return attribute(name, detail::number(value));
}

std::string attribute_integer(std::string_view name, std::size_t value)
{
    return attribute(name, std::to_string(value));
}

void write_metrics(XmlWriter &xml, const scanengine::ScanMetrics &metrics, std::size_t depth)
{
    xml.open(depth, "timing-metrics");
    xml.element(depth + 1U, "total-queued", std::to_string(metrics.total_queued));
    xml.element(depth + 1U, "total-submitted", std::to_string(metrics.total_submitted));
    xml.element(depth + 1U, "completed", std::to_string(metrics.completed));
    xml.element(depth + 1U, "timed-out", std::to_string(metrics.timed_out));
    xml.element(depth + 1U, "failed", std::to_string(metrics.failed));
    xml.element(depth + 1U, "cancelled", std::to_string(metrics.cancelled));
    xml.element(depth + 1U, "duplicate-responses", std::to_string(metrics.duplicate_responses));
    xml.element(depth + 1U, "late-responses", std::to_string(metrics.late_responses));
    xml.element(depth + 1U, "malformed-responses", std::to_string(metrics.malformed_responses));
    xml.element(depth + 1U, "current-parallelism", std::to_string(metrics.current_parallelism));
    xml.element(depth + 1U, "maximum-observed-parallelism",
                std::to_string(metrics.maximum_observed_parallelism));
    if (metrics.current_rtt_ms.has_value()) {
        xml.element(depth + 1U, "current-rtt-ms", detail::number(*metrics.current_rtt_ms));
    }
    if (metrics.minimum_rtt_ms.has_value()) {
        xml.element(depth + 1U, "minimum-rtt-ms", detail::number(*metrics.minimum_rtt_ms));
    }
    if (metrics.maximum_rtt_ms.has_value()) {
        xml.element(depth + 1U, "maximum-rtt-ms", detail::number(*metrics.maximum_rtt_ms));
    }
    if (metrics.rtt_samples > 0U) {
        xml.element(depth + 1U, "average-rtt-ms", detail::number(metrics.average_rtt_ms));
    }
    xml.element(depth + 1U, "rtt-samples", std::to_string(metrics.rtt_samples));
    xml.element(depth + 1U, "timeout-count", std::to_string(metrics.timeout_count));
    xml.element(depth + 1U, "retry-count", std::to_string(metrics.retry_count));
    xml.element(depth + 1U, "estimated-drop-rate", detail::number(metrics.estimated_drop_rate));
    xml.element(depth + 1U, "elapsed-ms", detail::number(static_cast<double>(metrics.elapsed().count())));
    xml.close(depth, "timing-metrics");
}

void write_port(XmlWriter &xml, const portscan::PortResult &port, std::size_t depth)
{
    std::string attributes = attribute("target", port.target) + attribute_integer("number", port.port.number) +
                             attribute("protocol", portscan::protocol_name(port.port.protocol)) +
                             attribute("state", portscan::port_state_name(port.state)) +
                             attribute("probe", portscan::scan_probe_type_name(port.probe)) +
                             attribute("reason", portscan::scan_reason_name(port.reason));
    if (port.rtt_ms.has_value()) {
        attributes += attribute_number("rtt-ms", *port.rtt_ms);
    }
    if (port.port.protocol == portscan::Protocol::Udp) {
        attributes += attribute_integer("retry-count", port.retry_count);
        attributes += attribute("probe-name", port.probe_name.value_or(""));
    }
    xml.self_closing(depth, "port", attributes);
}

void write_service(XmlWriter &xml, const detect::ServiceResult &service, std::size_t depth)
{
    std::string attributes = attribute("target", service.target) + attribute_integer("number", service.port.number) +
                             attribute("protocol", portscan::protocol_name(service.protocol)) +
                             attribute("port-state", portscan::port_state_name(service.port_state)) +
                             attribute("state", detect::detection_state_name(service.state)) +
                             attribute_number("confidence", service.confidence) +
                             attribute("method", detect::detection_method_name(service.method)) +
                             attribute("error", detect::detection_error_name(service.error));
    if (service.rtt_ms.has_value()) {
        attributes += attribute_number("rtt-ms", *service.rtt_ms);
    }
    if (service.service.empty() && service.product.empty() && service.version.empty() && service.extra.empty() &&
        service.probe_name.empty()) {
        xml.self_closing(depth, "service", attributes);
        return;
    }
    xml.open(depth, "service" + attributes);
    if (!service.service.empty()) {
        xml.element(depth + 1U, "name", service.service);
    }
    if (!service.product.empty()) {
        xml.element(depth + 1U, "product", service.product);
    }
    if (!service.version.empty()) {
        xml.element(depth + 1U, "version", service.version);
    }
    if (!service.extra.empty()) {
        xml.element(depth + 1U, "extra", service.extra);
    }
    if (!service.probe_name.empty()) {
        xml.element(depth + 1U, "probe", service.probe_name);
    }
    xml.close(depth, "service");
}

void write_os_detection(XmlWriter &xml, const osdetect::OSDetectionResult &result, std::size_t depth)
{
    xml.open(depth, "os-detection");
    xml.element(depth + 1U, "state", osdetect::os_detection_state_name(result.state));
    xml.element(depth + 1U, "error", osdetect::os_detection_error_name(result.error));
    xml.element(depth + 1U, "confidence", detail::number(result.confidence));
    xml.element(depth + 1U, "probes-sent", std::to_string(result.probes_sent));
    xml.element(depth + 1U, "responses-received", std::to_string(result.responses_received));
    xml.element(depth + 1U, "probes-timed-out", std::to_string(result.probes_timed_out));
    xml.element(depth + 1U, "tcp-evidence", std::to_string(result.observed.tcp_observations.size()));
    xml.element(depth + 1U, "icmp-evidence", std::to_string(result.observed.icmp_observations.size()));
    xml.element(depth + 1U, "udp-evidence", std::to_string(result.observed.udp_observations.size()));
    if (result.rtt_ms.has_value()) {
        xml.element(depth + 1U, "rtt-ms", detail::number(*result.rtt_ms));
    }
    xml.close(depth, "os-detection");
}

void write_os_match(XmlWriter &xml, const osdetect::OSMatchResult &match, std::size_t depth)
{
    std::string attributes = attribute("name", match.fingerprint_name) + attribute_number("confidence", match.confidence) +
                             attribute("confidence-class", db::match_category_name(match.category));
    if (!match.vendor.empty()) {
        attributes += attribute("vendor", match.vendor);
    }
    if (!match.family.empty()) {
        attributes += attribute("family", match.family);
    }
    if (!match.generation.empty()) {
        attributes += attribute("generation", match.generation);
    }
    if (!match.device_type.empty()) {
        attributes += attribute("device-type", match.device_type);
    }
    xml.self_closing(depth, "match", attributes);
}

void write_string_elements(XmlWriter &xml, const std::vector<std::string> &values, std::size_t depth,
                           std::string_view name)
{
    for (const std::string &value : values) {
        xml.element(depth, name, value);
    }
}

} // namespace

OutputFormat XmlOutputWriter::format() const noexcept
{
    return OutputFormat::Xml;
}

OutputStatus XmlOutputWriter::write(
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context) const
{
    if (validate_report(report) != OutputStatus::Ok) {
        return OutputStatus::InvalidReport;
    }
    XmlWriter xml(output, context.pretty_xml);
    xml.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.newline();
    xml.indent(0U);
    xml.raw("<skan" + attribute("version", report.scanner_version) + ">");
    xml.newline();
    xml.open(1U, "scan");
    if (report.started_at.has_value()) {
        xml.element(2U, "started-at", *report.started_at);
    }
    if (report.finished_at.has_value()) {
        xml.element(2U, "finished-at", *report.finished_at);
    }
    if (report.duration_ms.has_value()) {
        xml.element(2U, "duration-ms", detail::number(*report.duration_ms));
    }
    if (report.target_spec.has_value()) {
        xml.element(2U, "target-spec", *report.target_spec);
    }
    if (report.timing_profile.has_value()) {
        xml.element(2U, "timing-profile", scanengine::timing_profile_name(*report.timing_profile));
    }
    if (report.timing_metrics.has_value()) {
        write_metrics(xml, *report.timing_metrics, 2U);
    }
    xml.close(1U, "scan");

    for (const HostResult *host : detail::ordered_hosts(report)) {
        std::string attributes = attribute("address", host->address) +
                                 attribute("state", discovery::host_state_name(host->state));
        if (context.include_hostnames && host->hostname.has_value()) {
            attributes += attribute("hostname", *host->hostname);
        }
        if (host->rtt_ms.has_value()) {
            attributes += attribute_number("rtt-ms", *host->rtt_ms);
        }
        xml.open(1U, "host" + attributes);
        const std::vector<portscan::PortResult> ports = detail::ordered_ports(*host, context);
        if (!ports.empty()) {
            xml.open(2U, "ports");
            for (const portscan::PortResult &port : ports) {
                write_port(xml, port, 3U);
            }
            xml.close(2U, "ports");
        }
        const std::vector<detect::ServiceResult> services = detail::ordered_services(*host);
        if (!services.empty()) {
            xml.open(2U, "services");
            for (const detect::ServiceResult &service : services) {
                write_service(xml, service, 3U);
            }
            xml.close(2U, "services");
        }
        if (host->os_detection.has_value()) {
            write_os_detection(xml, *host->os_detection, 2U);
        }
        const std::vector<osdetect::OSMatchResult> matches = detail::ordered_os_matches(*host);
        if (!matches.empty()) {
            xml.open(2U, "os");
            for (const osdetect::OSMatchResult &match : matches) {
                write_os_match(xml, match, 3U);
            }
            xml.close(2U, "os");
        }
        if (!host->warnings.empty()) {
            xml.open(2U, "warnings");
            write_string_elements(xml, host->warnings, 3U, "warning");
            xml.close(2U, "warnings");
        }
        if (!host->errors.empty()) {
            xml.open(2U, "errors");
            write_string_elements(xml, host->errors, 3U, "error");
            xml.close(2U, "errors");
        }
        xml.close(1U, "host");
    }

    const ScanSummary summary = calculate_summary(report);
    xml.open(1U, "summary");
    xml.element(2U, "hosts", std::to_string(summary.hosts));
    xml.element(2U, "hosts-up", std::to_string(summary.hosts_up));
    xml.element(2U, "hosts-down", std::to_string(summary.hosts_down));
    xml.element(2U, "hosts-unknown", std::to_string(summary.hosts_unknown));
    xml.element(2U, "ports-scanned", std::to_string(summary.ports_scanned));
    xml.element(2U, "open-ports", std::to_string(summary.open_ports));
    xml.element(2U, "closed-ports", std::to_string(summary.closed_ports));
    xml.element(2U, "filtered-ports", std::to_string(summary.filtered_ports));
    xml.element(2U, "open-or-filtered-ports", std::to_string(summary.open_or_filtered_ports));
    xml.element(2U, "unfiltered-ports", std::to_string(summary.unfiltered_ports));
    xml.element(2U, "error-ports", std::to_string(summary.error_ports));
    xml.element(2U, "unknown-ports", std::to_string(summary.unknown_ports));
    xml.element(2U, "services-detected", std::to_string(summary.services_detected));
    xml.element(2U, "os-matches", std::to_string(summary.os_matches));
    xml.close(1U, "summary");
    if (!report.warnings.empty()) {
        xml.open(1U, "warnings");
        write_string_elements(xml, report.warnings, 2U, "warning");
        xml.close(1U, "warnings");
    }
    if (!report.errors.empty()) {
        xml.open(1U, "errors");
        write_string_elements(xml, report.errors, 2U, "error");
        xml.close(1U, "errors");
    }
    xml.raw("</skan>");
    xml.newline();
    return detail::check_stream(output);
}

} // namespace skan::output
