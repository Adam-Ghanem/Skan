#include "output/output_json.hpp"

#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace skan::output {
namespace {

class JsonWriter final {
public:
    JsonWriter(std::ostream &output, bool pretty) : output_(output), pretty_(pretty) {}

    void begin_object()
    {
        output_ << '{';
    }

    void end_object(std::size_t depth, bool has_values)
    {
        if (pretty_ && has_values) {
            newline(depth);
        }
        output_ << '}';
    }

    void begin_array()
    {
        output_ << '[';
    }

    void end_array(std::size_t depth, bool has_values)
    {
        if (pretty_ && has_values) {
            newline(depth);
        }
        output_ << ']';
    }

    void key(std::string_view name, bool &first, std::size_t depth)
    {
        if (!first) {
            output_ << ',';
        }
        if (pretty_) {
            newline(depth);
        }
        output_ << '"' << detail::json_escape(name) << "\": ";
        first = false;
    }

    void array_value(bool &first, std::size_t depth)
    {
        if (!first) {
            output_ << ',';
        }
        if (pretty_) {
            newline(depth);
        }
        first = false;
    }

    void string(std::string_view value)
    {
        output_ << '"' << detail::json_escape(value) << '"';
    }

    void number(double value)
    {
        output_ << detail::number(value);
    }

    void integer(std::size_t value)
    {
        output_ << value;
    }

    void boolean(bool value)
    {
        output_ << (value ? "true" : "false");
    }

    void newline(std::size_t depth)
    {
        output_ << '\n' << std::string(depth * 2U, ' ');
    }

private:
    std::ostream &output_;
    bool pretty_;
};

void write_string_array(JsonWriter &json, const std::vector<std::string> &values, std::size_t depth)
{
    json.begin_array();
    bool first = true;
    for (const std::string &value : values) {
        json.array_value(first, depth);
        json.string(value);
    }
    json.end_array(depth - 1U, !first);
}

void write_timing_metrics(JsonWriter &json, const scanengine::ScanMetrics &metrics, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("total_queued", first, depth + 1U);
    json.integer(metrics.total_queued);
    json.key("targets_total", first, depth + 1U);
    json.integer(metrics.targets_total);
    json.key("targets_completed", first, depth + 1U);
    json.integer(metrics.targets_completed);
    json.key("targets_failed", first, depth + 1U);
    json.integer(metrics.targets_failed);
    json.key("probes_submitted", first, depth + 1U);
    json.integer(metrics.probes_submitted);
    json.key("probes_completed", first, depth + 1U);
    json.integer(metrics.probes_completed);
    json.key("probes_timed_out", first, depth + 1U);
    json.integer(metrics.probes_timed_out);
    json.key("probes_failed", first, depth + 1U);
    json.integer(metrics.probes_failed);
    json.key("probes_cancelled", first, depth + 1U);
    json.integer(metrics.probes_cancelled);
    json.key("probes_retried", first, depth + 1U);
    json.integer(metrics.probes_retried);
    json.key("retries", first, depth + 1U);
    json.integer(metrics.retries);
    json.key("bytes_sent", first, depth + 1U);
    json.integer(metrics.bytes_sent);
    json.key("bytes_received", first, depth + 1U);
    json.integer(metrics.bytes_received);
    json.key("total_submitted", first, depth + 1U);
    json.integer(metrics.total_submitted);
    json.key("completed", first, depth + 1U);
    json.integer(metrics.completed);
    json.key("timed_out", first, depth + 1U);
    json.integer(metrics.timed_out);
    json.key("failed", first, depth + 1U);
    json.integer(metrics.failed);
    json.key("cancelled", first, depth + 1U);
    json.integer(metrics.cancelled);
    json.key("duplicate_responses", first, depth + 1U);
    json.integer(metrics.duplicate_responses);
    json.key("late_responses", first, depth + 1U);
    json.integer(metrics.late_responses);
    json.key("malformed_responses", first, depth + 1U);
    json.integer(metrics.malformed_responses);
    json.key("parse_errors", first, depth + 1U);
    json.integer(metrics.parse_errors);
    json.key("correlation_misses", first, depth + 1U);
    json.integer(metrics.correlation_misses);
    json.key("active_probes", first, depth + 1U);
    json.integer(metrics.active_probes);
    json.key("peak_active_probes", first, depth + 1U);
    json.integer(metrics.peak_active_probes);
    json.key("current_parallelism", first, depth + 1U);
    json.integer(metrics.current_parallelism);
    json.key("maximum_observed_parallelism", first, depth + 1U);
    json.integer(metrics.maximum_observed_parallelism);
    if (metrics.current_rtt_ms.has_value()) {
        json.key("current_rtt_ms", first, depth + 1U);
        json.number(*metrics.current_rtt_ms);
    }
    if (metrics.minimum_rtt_ms.has_value()) {
        json.key("minimum_rtt_ms", first, depth + 1U);
        json.number(*metrics.minimum_rtt_ms);
    }
    if (metrics.maximum_rtt_ms.has_value()) {
        json.key("maximum_rtt_ms", first, depth + 1U);
        json.number(*metrics.maximum_rtt_ms);
    }
    if (metrics.srtt_ms.has_value()) {
        json.key("srtt_ms", first, depth + 1U);
        json.number(*metrics.srtt_ms);
    }
    if (metrics.rttvar_ms.has_value()) {
        json.key("rttvar_ms", first, depth + 1U);
        json.number(*metrics.rttvar_ms);
    }
    if (metrics.rto_ms.has_value()) {
        json.key("rto_ms", first, depth + 1U);
        json.number(*metrics.rto_ms);
    }
    if (metrics.rtt_samples > 0U) {
        json.key("average_rtt_ms", first, depth + 1U);
        json.number(metrics.average_rtt_ms);
    }
    json.key("rtt_samples", first, depth + 1U);
    json.integer(metrics.rtt_samples);
    json.key("timeout_count", first, depth + 1U);
    json.integer(metrics.timeout_count);
    json.key("retry_count", first, depth + 1U);
    json.integer(metrics.retry_count);
    json.key("timeout_backoffs", first, depth + 1U);
    json.integer(metrics.timeout_backoffs);
    json.key("estimated_drop_rate", first, depth + 1U);
    json.number(metrics.estimated_drop_rate);
    json.key("elapsed_ms", first, depth + 1U);
    json.number(static_cast<double>(metrics.elapsed().count()));
    json.key("stage_duration_ms", first, depth + 1U);
    json.begin_array();
    bool first_stage = true;
    for (const double duration : metrics.stage_duration_ms) {
        json.array_value(first_stage, depth + 1U);
        json.number(duration);
    }
    json.end_array(depth, !first_stage);
    json.end_object(depth, !first);
}

void write_port(JsonWriter &json, const portscan::PortResult &port, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("target", first, depth + 1U);
    json.string(port.target);
    json.key("port", first, depth + 1U);
    json.integer(port.port.number);
    json.key("protocol", first, depth + 1U);
    json.string(portscan::protocol_name(port.port.protocol));
    json.key("state", first, depth + 1U);
    json.string(portscan::port_state_name(port.state));
    json.key("probe", first, depth + 1U);
    json.string(portscan::scan_probe_type_name(port.probe));
    json.key("reason", first, depth + 1U);
    json.string(portscan::scan_reason_name(port.reason));
    if (port.rtt_ms.has_value()) {
        json.key("rtt_ms", first, depth + 1U);
        json.number(*port.rtt_ms);
    }
    if (port.port.protocol == portscan::Protocol::Udp) {
        json.key("retry_count", first, depth + 1U);
        json.integer(port.retry_count);
        if (port.probe_name.has_value()) {
            json.key("probe_name", first, depth + 1U);
            json.string(*port.probe_name);
        }
    }
    json.end_object(depth, !first);
}

void write_service(JsonWriter &json, const detect::ServiceResult &service, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("target", first, depth + 1U);
    json.string(service.target);
    json.key("port", first, depth + 1U);
    json.integer(service.port.number);
    json.key("protocol", first, depth + 1U);
    json.string(portscan::protocol_name(service.protocol));
    json.key("port_state", first, depth + 1U);
    json.string(portscan::port_state_name(service.port_state));
    json.key("state", first, depth + 1U);
    json.string(detect::detection_state_name(service.state));
    if (!service.service.empty()) {
        json.key("service", first, depth + 1U);
        json.string(service.service);
    }
    if (!service.product.empty()) {
        json.key("product", first, depth + 1U);
        json.string(service.product);
    }
    if (!service.version.empty()) {
        json.key("version", first, depth + 1U);
        json.string(service.version);
    }
    if (!service.extra.empty()) {
        json.key("extra", first, depth + 1U);
        json.string(service.extra);
    }
    json.key("confidence", first, depth + 1U);
    json.number(service.confidence);
    json.key("method", first, depth + 1U);
    json.string(detect::detection_method_name(service.method));
    if (!service.probe_name.empty()) {
        json.key("probe", first, depth + 1U);
        json.string(service.probe_name);
    }
    if (service.rtt_ms.has_value()) {
        json.key("rtt_ms", first, depth + 1U);
        json.number(*service.rtt_ms);
    }
    json.key("error", first, depth + 1U);
    json.string(detect::detection_error_name(service.error));
    json.end_object(depth, !first);
}

void write_os_match(JsonWriter &json, const osdetect::OSMatchResult &match, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("name", first, depth + 1U);
    json.string(match.fingerprint_name);
    json.key("id", first, depth + 1U);
    json.string(match.fingerprint_id);
    if (!match.vendor.empty()) {
        json.key("vendor", first, depth + 1U);
        json.string(match.vendor);
    }
    if (!match.family.empty()) {
        json.key("family", first, depth + 1U);
        json.string(match.family);
    }
    if (!match.generation.empty()) {
        json.key("generation", first, depth + 1U);
        json.string(match.generation);
    }
    if (!match.device_type.empty()) {
        json.key("device_type", first, depth + 1U);
        json.string(match.device_type);
    }
    json.key("confidence", first, depth + 1U);
    json.number(match.confidence);
    json.key("confidence_class", first, depth + 1U);
    json.string(db::match_category_name(match.category));
    json.key("matched_fields", first, depth + 1U);
    write_string_array(json, match.matched_fields, depth + 2U);
    json.key("mismatched_fields", first, depth + 1U);
    write_string_array(json, match.mismatched_fields, depth + 2U);
    json.key("unavailable_fields", first, depth + 1U);
    write_string_array(json, match.unavailable_fields, depth + 2U);
    json.end_object(depth, !first);
}

void write_os_detection(JsonWriter &json, const osdetect::OSDetectionResult &result, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("address_family", first, depth + 1U);
    json.string(core::address_family_name(result.address_family));
    json.key("state", first, depth + 1U);
    json.string(osdetect::os_detection_state_name(result.state));
    json.key("error", first, depth + 1U);
    json.string(osdetect::os_detection_error_name(result.error));
    if (!result.vendor.empty()) {
        json.key("vendor", first, depth + 1U);
        json.string(result.vendor);
    }
    if (!result.family.empty()) {
        json.key("family", first, depth + 1U);
        json.string(result.family);
    }
    if (!result.generation.empty()) {
        json.key("generation", first, depth + 1U);
        json.string(result.generation);
    }
    if (!result.device_type.empty()) {
        json.key("device_type", first, depth + 1U);
        json.string(result.device_type);
    }
    json.key("confidence", first, depth + 1U);
    json.number(result.confidence);
    if (!result.fingerprint_id.empty()) {
        json.key("fingerprint_id", first, depth + 1U);
        json.string(result.fingerprint_id);
    }
    json.key("probes_generated", first, depth + 1U);
    json.integer(result.probes_generated);
    json.key("probes_sent", first, depth + 1U);
    json.integer(result.probes_sent);
    json.key("responses_received", first, depth + 1U);
    json.integer(result.responses_received);
    json.key("probes_timed_out", first, depth + 1U);
    json.integer(result.probes_timed_out);
    json.key("probes_unsupported", first, depth + 1U);
    json.integer(result.probes_unsupported);
    json.key("probes_malformed", first, depth + 1U);
    json.integer(result.probes_malformed);
    if (result.rtt_ms.has_value()) {
        json.key("rtt_ms", first, depth + 1U);
        json.number(*result.rtt_ms);
    }
    json.key("tcp_observations", first, depth + 1U);
    json.integer(result.observed.tcp_observations.size());
    json.key("icmp_observations", first, depth + 1U);
    json.integer(result.observed.icmp_observations.size());
    json.key("udp_observations", first, depth + 1U);
    json.integer(result.observed.udp_observations.size());
    json.end_object(depth, !first);
}

void write_host(JsonWriter &json, const HostResult &host, const OutputContext &context, std::size_t depth)
{
    json.begin_object();
    bool first = true;
    json.key("address", first, depth + 1U);
    json.string(host.address);
    json.key("family", first, depth + 1U);
    json.string(core::address_family_name(host.family));
    if (context.include_hostnames && host.hostname.has_value()) {
        json.key("hostname", first, depth + 1U);
        json.string(*host.hostname);
    }
    json.key("state", first, depth + 1U);
    json.string(discovery::host_state_name(host.state));
    if (host.rtt_ms.has_value()) {
        json.key("rtt_ms", first, depth + 1U);
        json.number(*host.rtt_ms);
    }
    json.key("ports", first, depth + 1U);
    json.begin_array();
    const std::vector<const portscan::PortResult *> ports = detail::ordered_ports(host, context);
    bool first_port = true;
    for (const portscan::PortResult *port : ports) {
        json.array_value(first_port, depth + 2U);
        write_port(json, *port, depth + 2U);
    }
    json.end_array(depth + 1U, !first_port);
    json.key("services", first, depth + 1U);
    json.begin_array();
    const std::vector<const detect::ServiceResult *> services = detail::ordered_services(host);
    bool first_service = true;
    for (const detect::ServiceResult *service : services) {
        json.array_value(first_service, depth + 2U);
        write_service(json, *service, depth + 2U);
    }
    json.end_array(depth + 1U, !first_service);
    json.key("os", first, depth + 1U);
    json.begin_array();
    const std::vector<const osdetect::OSMatchResult *> matches = detail::ordered_os_matches(host);
    bool first_match = true;
    for (const osdetect::OSMatchResult *match : matches) {
        json.array_value(first_match, depth + 2U);
        write_os_match(json, *match, depth + 2U);
    }
    json.end_array(depth + 1U, !first_match);
    if (host.os_detection.has_value()) {
        json.key("os_detection", first, depth + 1U);
        write_os_detection(json, *host.os_detection, depth + 1U);
    }
    json.key("warnings", first, depth + 1U);
    write_string_array(json, host.warnings, depth + 2U);
    json.key("errors", first, depth + 1U);
    write_string_array(json, host.errors, depth + 2U);
    json.end_object(depth, !first);
}

} // namespace

OutputFormat JsonOutputWriter::format() const noexcept
{
    return OutputFormat::Json;
}

OutputStatus JsonOutputWriter::write(
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context) const
{
    if (validate_report(report) != OutputStatus::Ok) {
        return OutputStatus::InvalidReport;
    }
    JsonWriter json(output, context.pretty_json);
    json.begin_object();
    bool first = true;
    json.key("scanner", first, 1U);
    json.begin_object();
    bool scanner_first = true;
    json.key("name", scanner_first, 2U);
    json.string(report.scanner_name);
    json.key("version", scanner_first, 2U);
    json.string(report.scanner_version);
    json.end_object(1U, !scanner_first);
    json.key("scan", first, 1U);
    json.begin_object();
    bool scan_first = true;
    if (report.started_at.has_value()) {
        json.key("started_at", scan_first, 2U);
        json.string(*report.started_at);
    }
    if (report.finished_at.has_value()) {
        json.key("finished_at", scan_first, 2U);
        json.string(*report.finished_at);
    }
    if (report.duration_ms.has_value()) {
        json.key("duration_ms", scan_first, 2U);
        json.number(*report.duration_ms);
    }
    if (report.target_spec.has_value()) {
        json.key("target_spec", scan_first, 2U);
        json.string(*report.target_spec);
    }
    if (report.timing_profile.has_value()) {
        json.key("timing_profile", scan_first, 2U);
        json.string(scanengine::timing_profile_name(*report.timing_profile));
    }
    if (report.timing_metrics.has_value()) {
        json.key("timing_metrics", scan_first, 2U);
        write_timing_metrics(json, *report.timing_metrics, 2U);
    }
    json.end_object(1U, !scan_first);
    json.key("hosts", first, 1U);
    json.begin_array();
    const std::vector<const HostResult *> hosts = detail::ordered_hosts(report);
    bool first_host = true;
    for (const HostResult *host : hosts) {
        json.array_value(first_host, 2U);
        write_host(json, *host, context, 2U);
    }
    json.end_array(1U, !first_host);
    const ScanSummary summary = calculate_summary(report);
    json.key("summary", first, 1U);
    json.begin_object();
    bool summary_first = true;
    json.key("hosts", summary_first, 2U);
    json.integer(summary.hosts);
    json.key("hosts_up", summary_first, 2U);
    json.integer(summary.hosts_up);
    json.key("hosts_down", summary_first, 2U);
    json.integer(summary.hosts_down);
    json.key("hosts_unknown", summary_first, 2U);
    json.integer(summary.hosts_unknown);
    json.key("ports_scanned", summary_first, 2U);
    json.integer(summary.ports_scanned);
    json.key("open_ports", summary_first, 2U);
    json.integer(summary.open_ports);
    json.key("closed_ports", summary_first, 2U);
    json.integer(summary.closed_ports);
    json.key("filtered_ports", summary_first, 2U);
    json.integer(summary.filtered_ports);
    json.key("open_or_filtered_ports", summary_first, 2U);
    json.integer(summary.open_or_filtered_ports);
    json.key("unfiltered_ports", summary_first, 2U);
    json.integer(summary.unfiltered_ports);
    json.key("error_ports", summary_first, 2U);
    json.integer(summary.error_ports);
    json.key("unknown_ports", summary_first, 2U);
    json.integer(summary.unknown_ports);
    json.key("services_detected", summary_first, 2U);
    json.integer(summary.services_detected);
    json.key("os_matches", summary_first, 2U);
    json.integer(summary.os_matches);
    json.end_object(1U, !summary_first);
    json.key("warnings", first, 1U);
    write_string_array(json, report.warnings, 2U);
    json.key("errors", first, 1U);
    write_string_array(json, report.errors, 2U);
    json.end_object(0U, !first);
    output << '\n';
    return detail::check_stream(output);
}

} // namespace skan::output
