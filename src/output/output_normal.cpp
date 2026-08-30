#include "output/output_normal.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdlib>
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

constexpr std::size_t kDefaultColumns = 96U;
constexpr std::size_t kNarrowColumns = 72U;

std::size_t terminal_columns() noexcept
{
    const char *value = std::getenv("COLUMNS");
    if (value == nullptr || *value == '\0') {
        return kDefaultColumns;
    }

    unsigned int parsed = 0U;
    const char *first = value;
    const char *last = value;
    while (*last != '\0') {
        ++last;
    }
    const auto result = std::from_chars(first, last, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != last || parsed < 40U || parsed > 300U) {
        return kDefaultColumns;
    }
    return static_cast<std::size_t>(parsed);
}

std::string paint(std::string_view text, std::string_view color, const OutputContext &context)
{
    if (!context.color_enabled) {
        return std::string(text);
    }
    return std::string(color) + std::string(text) + std::string(kReset);
}


std::string repeat(std::string_view token, std::size_t count)
{
    std::string value;
    value.reserve(token.size() * count);
    for (std::size_t index = 0U; index < count; ++index) {
        value.append(token);
    }
    return value;
}

std::string truncate(std::string_view value, std::size_t width)
{
    if (value.size() <= width) {
        return std::string(value);
    }
    if (width <= 3U) {
        return std::string(value.substr(0U, width));
    }
    return std::string(value.substr(0U, width - 3U)) + "...";
}

std::string padded_cell(
    std::string_view value,
    std::size_t width,
    const OutputContext &context,
    std::string_view color = {})
{
    const std::string fitted = truncate(value, width);
    std::string rendered = color.empty() ? fitted : paint(fitted, color, context);
    if (fitted.size() < width) {
        rendered.append(width - fitted.size(), ' ');
    }
    return rendered;
}

std::string state_color(portscan::PortState state)
{
    switch (state) {
    case portscan::PortState::Open:
        return std::string(kGreen);
    case portscan::PortState::Filtered:
    case portscan::PortState::OpenOrFiltered:
        return std::string(kYellow);
    case portscan::PortState::Closed:
    case portscan::PortState::Error:
    case portscan::PortState::Unreachable:
        return std::string(kRed);
    case portscan::PortState::Unfiltered:
    case portscan::PortState::Unknown:
        return std::string(kDim);
    }
    return {};
}

std::string format_ms(double value)
{
    std::ostringstream stream;
    if (value < 10.0) {
        stream << std::fixed << std::setprecision(2) << value;
    } else if (value < 100.0) {
        stream << std::fixed << std::setprecision(1) << value;
    } else {
        stream << std::fixed << std::setprecision(0) << value;
    }
    return stream.str() + " ms";
}

std::string clean_version(const ScanReport &report)
{
    std::string value = report.scanner_version;
    const std::string prefix = report.scanner_name + " ";
    if (value.rfind(prefix, 0U) == 0U) {
        value.erase(0U, prefix.size());
    }
    if (!value.empty() && value.front() == 'v') {
        return value;
    }
    return "v" + value;
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
    if (!service->tunnel.empty()) {
        if (!value.empty()) {
            value += " · ";
        }
        value += detail::grep_escape(service->tunnel);
    }
    return value.empty() ? "-" : value;
}

bool has_reachability_evidence(const HostResult &host) noexcept
{
    for (const portscan::PortResult &port : host.ports) {
        if (port.state == portscan::PortState::Open || port.state == portscan::PortState::Closed ||
            port.state == portscan::PortState::Unfiltered) {
            return true;
        }
    }
    return false;
}

std::string host_status(const HostResult &host)
{
    if (host.state == discovery::HostState::Up || has_reachability_evidence(host)) {
        return "reachable";
    }
    switch (host.state) {
    case discovery::HostState::Down:
        return "down";
    case discovery::HostState::Unreachable:
        return "unreachable";
    case discovery::HostState::Unknown:
        return "unknown";
    case discovery::HostState::Up:
        return "reachable";
    }
    return "unknown";
}

std::string host_status_color(const HostResult &host)
{
    const std::string status = host_status(host);
    if (status == "reachable") {
        return std::string(kGreen);
    }
    if (status == "down" || status == "unreachable") {
        return std::string(kRed);
    }
    return std::string(kYellow);
}

std::optional<double> host_latency(const HostResult &host)
{
    if (host.rtt_ms.has_value()) {
        return host.rtt_ms;
    }
    for (const portscan::PortResult &port : host.ports) {
        if ((port.state == portscan::PortState::Open || port.state == portscan::PortState::Closed ||
             port.state == portscan::PortState::Unfiltered) &&
            port.rtt_ms.has_value()) {
            return port.rtt_ms;
        }
    }
    return std::nullopt;
}

void write_brand(std::ostream &output, const ScanReport &report, const OutputContext &context, std::size_t columns)
{
    const std::string version = clean_version(report);
    if (!context.interactive_terminal) {
        output << "SKAN " << version << '\n';
        return;
    }
    if (columns < kNarrowColumns) {
        output << paint("SKAN", kCyan, context) << ' ' << paint(version, kDim, context) << '\n'
               << paint("Modern Network Scanner", kDim, context) << "\n\n";
        return;
    }

    constexpr std::size_t width = 68U;
    const std::string title = "◈ SKAN";
    const std::string subtitle = "Modern Network Scanner";
    output << "╭─ " << paint(title, kCyan, context) << ' ' << std::string(56U, ' ') << "╮\n";
    output << "│  " << paint(subtitle, kDim, context);
    const std::size_t used = 2U + subtitle.size() + version.size();
    if (used < width - 1U) {
        output << std::string(width - used - 1U, ' ');
    } else {
        output << ' ';
    }
    output << paint(version, kCyan, context) << " │\n";
    output << "╰" << repeat("─", width) << "╯\n\n";
}

void write_host_heading(std::ostream &output, const HostResult &host, const OutputContext &context, std::size_t columns)
{
    const std::string status = host_status(host);
    const bool reachable = status == "reachable";
    const std::string marker = reachable ? "●" : "○";

    std::string identity = detail::grep_escape(host.address);
    if (context.include_hostnames && host.hostname.has_value()) {
        identity += " (" + detail::grep_escape(*host.hostname) + ')';
    }

    std::string suffix = " · " + status;
    if (const std::optional<double> latency = host_latency(host); latency.has_value()) {
        suffix += " · " + format_ms(*latency);
    }

    const std::size_t reserved = marker.size() + 2U + suffix.size();
    const std::size_t max_identity = columns > reserved ? columns - reserved : 16U;
    if (!context.interactive_terminal) {
        output << "Host " << truncate(identity, max_identity) << " · " << status;
    } else {
        output << paint(marker, reachable ? kGreen : kDim, context) << ' '
               << paint(truncate(identity, max_identity), kCyan, context)
               << " · " << paint(status, host_status_color(host), context);
    }
    if (const std::optional<double> latency = host_latency(host); latency.has_value()) {
        output << " · ";
        if (context.interactive_terminal) {
            output << paint(format_ms(*latency), kDim, context);
        } else {
            output << format_ms(*latency);
        }
    }
    output << '\n';
}

void write_port_table(
    std::ostream &output,
    const HostResult &host,
    const std::vector<const portscan::PortResult *> &ports,
    const OutputContext &context,
    std::size_t columns)
{
    if (ports.empty()) {
        output << "  " << paint("No port rows matched the selected output filters.", kDim, context) << "\n";
        return;
    }

    const std::vector<const detect::ServiceResult *> services = detail::ordered_services(host);
    const bool narrow = columns < kNarrowColumns;

    if (narrow) {
        output << "\n  " << paint("PORT", kCyan, context)
               << "      " << paint("STATE", kCyan, context)
               << "     " << paint("SERVICE", kCyan, context) << '\n';
        output << "  ----------------------------------------------------------\n";
        for (const portscan::PortResult *port : ports) {
            std::ostringstream endpoint;
            endpoint << port->port.number << '/' << portscan::protocol_name(port->port.protocol);
            const detect::ServiceResult *service = service_for(services, *port);
            const std::string state = portscan::port_state_name(port->state);
            output << "  " << padded_cell(endpoint.str(), 10U, context)
                   << padded_cell(state, 10U, context, state_color(port->state))
                   << truncate(service_label(service), columns > 22U ? columns - 22U : 18U) << '\n';
            const std::string version = version_label(service);
            if (version != "-") {
                output << "    version: " << truncate(version, columns > 13U ? columns - 13U : 24U) << '\n';
            }
            if (context.include_reasons) {
                output << "    reason: " << truncate(portscan::scan_reason_name(port->reason), columns > 12U ? columns - 12U : 24U)
                       << '\n';
            }
        }
        return;
    }

    constexpr std::size_t port_width = 12U;
    constexpr std::size_t state_width = 13U;
    constexpr std::size_t service_width = 14U;
    constexpr std::size_t version_width = 28U;

    output << "\n  " << padded_cell("PORT", port_width, context, kCyan)
           << padded_cell("STATE", state_width, context, kCyan)
           << padded_cell("SERVICE", service_width, context, kCyan)
           << padded_cell("VERSION", version_width, context, kCyan);
    if (context.include_reasons) {
        output << paint("REASON", kCyan, context);
    }
    output << '\n';

    const std::size_t rule_width = context.include_reasons ? 89U : 67U;
    output << "  " << std::string(rule_width, '-') << '\n';

    for (const portscan::PortResult *port : ports) {
        std::ostringstream endpoint;
        endpoint << port->port.number << '/' << portscan::protocol_name(port->port.protocol);
        const detect::ServiceResult *service = service_for(services, *port);
        const std::string state = portscan::port_state_name(port->state);
        output << "  " << padded_cell(endpoint.str(), port_width, context)
               << padded_cell(state, state_width, context, state_color(port->state))
               << padded_cell(service_label(service), service_width, context)
               << padded_cell(version_label(service), version_width, context);
        if (context.include_reasons) {
            output << truncate(portscan::scan_reason_name(port->reason), 22U);
        }
        output << '\n';
    }
}

void write_os_summary(
    std::ostream &output,
    const HostResult &host,
    const OutputContext &context,
    std::size_t columns)
{
    if (!host.os_detection.has_value()) {
        return;
    }
    const osdetect::OSDetectionResult &detection = *host.os_detection;
    if (detection.family.empty() && detection.vendor.empty()) {
        return;
    }

    std::string label;
    if (!detection.vendor.empty()) {
        label += detail::grep_escape(detection.vendor);
    }
    if (!detection.family.empty()) {
        if (!label.empty()) {
            label.push_back(' ');
        }
        label += detail::grep_escape(detection.family);
    }
    if (!detection.generation.empty()) {
        label += " " + detail::grep_escape(detection.generation);
    }

    const osdetect::OSMatchResult *selected_match = nullptr;
    for (const osdetect::OSMatchResult &match : host.os_matches) {
        if (match.vendor == detection.vendor && match.family == detection.family &&
            match.generation == detection.generation) {
            if (selected_match == nullptr || match.confidence > selected_match->confidence) {
                selected_match = &match;
            }
        }
    }
    if (selected_match == nullptr && !host.os_matches.empty()) {
        selected_match = &host.os_matches.front();
    }
    if (selected_match != nullptr && !selected_match->fingerprint_name.empty()) {
        label += " · " + detail::grep_escape(selected_match->fingerprint_name);
    }

    const int confidence = static_cast<int>(std::lround(detection.confidence * 100.0));
    if (confidence > 0) {
        label += " · " + std::to_string(confidence) + '%';
    }

    const std::size_t prefix_width = 6U;
    const std::size_t available = columns > prefix_width ? columns - prefix_width : 24U;
    output << "  " << paint("OS", kCyan, context) << "  " << truncate(label, available) << '\n';
}

void write_summary(std::ostream &output, const ScanReport &report, const OutputContext &context)
{
    const ScanSummary summary = calculate_summary(report);
    output << '\n' << paint("Scan Summary", kCyan, context) << '\n';
    output << paint("Scan complete", kBold, context);
    if (report.duration_ms.has_value()) {
        output << " · " << paint(format_ms(*report.duration_ms), kDim, context);
    }
    output << '\n';
    output << "  " << paint(std::to_string(summary.open_ports) + " open", kGreen, context)
           << " · " << paint(std::to_string(summary.closed_ports) + " closed", kRed, context)
           << " · " << paint(std::to_string(summary.filtered_ports) + " filtered", kYellow, context)
           << " · " << summary.ports_scanned << " scanned";
    if (summary.services_detected > 0U) {
        output << " · " << summary.services_detected << " service";
        if (summary.services_detected != 1U) {
            output << 's';
        }
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

    const std::size_t columns = terminal_columns();
    write_brand(output, report, context, columns);

    if (report.target_spec.has_value()) {
        const std::string target = detail::grep_escape(*report.target_spec);
        output << paint("Target", kDim, context) << "  " << paint(truncate(target, columns > 8U ? columns - 8U : 24U), kCyan, context)
               << "\n\n";
    }

    for (const HostResult *host : detail::ordered_hosts(report)) {
        write_host_heading(output, *host, context, columns);
        const std::vector<const portscan::PortResult *> ports = detail::ordered_ports(*host, context);
        write_port_table(output, *host, ports, context, columns);
        write_os_summary(output, *host, context, columns);

        for (const std::string &warning : host->warnings) {
            output << "  " << paint("!", kYellow, context) << ' ' << truncate(detail::grep_escape(warning), columns > 4U ? columns - 4U : 24U)
                   << '\n';
        }
        for (const std::string &error : host->errors) {
            output << "  " << paint("×", kRed, context) << ' ' << truncate(detail::grep_escape(error), columns > 4U ? columns - 4U : 24U)
                   << '\n';
        }
        output << '\n';
    }

    write_summary(output, report, context);

    if (!report.warnings.empty()) {
        output << paint("Warnings", kYellow, context) << '\n';
        for (const std::string &warning : report.warnings) {
            output << "  - " << truncate(detail::grep_escape(warning), columns > 4U ? columns - 4U : 24U) << '\n';
        }
    }
    if (!report.errors.empty()) {
        output << paint("Errors", kRed, context) << '\n';
        for (const std::string &error : report.errors) {
            output << "  - " << truncate(detail::grep_escape(error), columns > 4U ? columns - 4U : 24U) << '\n';
        }
    }

    if (context.interactive_terminal && columns >= kNarrowColumns) {
        output << '\n' << paint("Skan", kCyan, context) << " — See more. Know more. Secure more.\n";
    }
    return detail::check_stream(output);
}

} // namespace skan::output
