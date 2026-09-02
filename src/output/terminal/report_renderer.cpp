#include "output/terminal/report_renderer.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "output/output_writer.hpp"
#include "output/terminal_layout.hpp"
#include "output/terminal_text.hpp"
#include "output/terminal_theme.hpp"

namespace skan::output {
namespace {

std::string repeat(std::string_view token, std::size_t count)
{
    std::string value;
    value.reserve(token.size() * count);
    for (std::size_t index = 0U; index < count; ++index) {
        value.append(token);
    }
    return value;
}

std::string ascii_safe(std::string_view value)
{
    const std::string sanitized = sanitize_terminal_text(value);
    std::string result;
    result.reserve(sanitized.size());
    for (const unsigned char byte : sanitized) {
        result.push_back(byte < 0x80U ? static_cast<char>(byte) : '?');
    }
    return result;
}

std::string clean_version(const ScanReport &report)
{
    std::string value = sanitize_terminal_text(report.scanner_version);
    const std::string prefix = sanitize_terminal_text(report.scanner_name) + " ";
    if (value.rfind(prefix, 0U) == 0U) {
        value.erase(0U, prefix.size());
    }
    if (!value.empty() && value.front() == 'v') {
        return value;
    }
    return "v" + value;
}

std::string format_ms(double value)
{
    std::ostringstream stream;
    if (value < 10.0) {
        stream << std::fixed << std::setprecision(2);
    } else if (value < 100.0) {
        stream << std::fixed << std::setprecision(1);
    } else {
        stream << std::fixed << std::setprecision(0);
    }
    stream << value << " ms";
    return stream.str();
}

bool has_reachability_evidence(const HostResult &host) noexcept
{
    return std::any_of(host.ports.begin(), host.ports.end(), [](const portscan::PortResult &port) {
        return port.state == portscan::PortState::Open || port.state == portscan::PortState::Closed ||
               port.state == portscan::PortState::Unfiltered;
    });
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

TerminalStyle state_style(portscan::PortState state) noexcept
{
    switch (state) {
    case portscan::PortState::Open:
        return TerminalStyle::Open;
    case portscan::PortState::Filtered:
    case portscan::PortState::OpenOrFiltered:
        return TerminalStyle::Filtered;
    case portscan::PortState::Closed:
    case portscan::PortState::Error:
    case portscan::PortState::Unreachable:
        return TerminalStyle::Closed;
    case portscan::PortState::Unfiltered:
    case portscan::PortState::Unknown:
        return TerminalStyle::Metadata;
    }
    return TerminalStyle::Metadata;
}

std::string fit(std::string_view value, std::size_t cells)
{
    return truncate_display(sanitize_terminal_text(value), cells);
}

std::string padded(std::string_view value, std::size_t cells)
{
    std::string result = fit(value, cells);
    const std::size_t width = display_width(result);
    if (width < cells) {
        result.append(cells - width, ' ');
    }
    return result;
}

std::string endpoint_label(const portscan::PortResult &port)
{
    return std::to_string(port.port.number) + "/" + portscan::protocol_name(port.port.protocol);
}

std::vector<const detect::ServiceResult *> services_for(
    const std::vector<const detect::ServiceResult *> &services,
    const portscan::PortResult &port)
{
    std::vector<const detect::ServiceResult *> matches;
    for (const detect::ServiceResult *service : services) {
        if (service->port.number == port.port.number && service->protocol == port.port.protocol &&
            service->state == detect::DetectionState::Detected) {
            matches.push_back(service);
        }
    }
    return matches;
}

std::string service_label(const detect::ServiceResult *service)
{
    return service == nullptr || service->service.empty() ? "-" : sanitize_terminal_text(service->service);
}

std::string version_label(const detect::ServiceResult *service, bool unicode)
{
    if (service == nullptr) {
        return "-";
    }
    std::string value;
    if (!service->product.empty()) {
        value = sanitize_terminal_text(service->product);
    }
    if (!service->version.empty()) {
        if (!value.empty()) {
            value.push_back(' ');
        }
        value += sanitize_terminal_text(service->version);
    }
    if (!service->tunnel.empty()) {
        if (!value.empty()) {
            value += unicode ? " · " : " / ";
        }
        value += sanitize_terminal_text(service->tunnel);
    }
    return value.empty() ? "-" : value;
}

class HeaderRenderer final {
public:
    void render(const ScanReport &report, std::ostream &output, const TerminalLayout &layout,
                const TerminalCapabilities &terminal, const TerminalTheme &theme) const
    {
        const std::string version = clean_version(report);
        if (layout.mode == TerminalLayoutMode::Plain) {
            output << "SKAN " << ascii_safe(version) << '\n';
            return;
        }
        const std::string mark = terminal.unicode ? "◈" : "*";
        if (layout.mode != TerminalLayoutMode::Wide) {
            output << theme.apply(mark + " SKAN", TerminalStyle::Brand) << ' '
                   << theme.apply(version, TerminalStyle::Metadata);
            if (layout.mode == TerminalLayoutMode::Medium) {
                output << "  " << theme.apply("Modern Network Scanner", TerminalStyle::Metadata);
            }
            output << "\n\n";
            return;
        }
        const std::string horizontal = terminal.unicode ? "─" : "-";
        const std::string top_left = terminal.unicode ? "╭" : "+";
        const std::string top_right = terminal.unicode ? "╮" : "+";
        const std::string bottom_left = terminal.unicode ? "╰" : "+";
        const std::string bottom_right = terminal.unicode ? "╯" : "+";
        const std::string vertical = terminal.unicode ? "│" : "|";
        output << top_left << repeat(horizontal, layout.columns - 2U) << top_right << '\n';
        const std::string left = "  " + mark + " SKAN  Modern Network Scanner";
        const std::size_t content_cells = layout.columns - 2U;
        const std::size_t right_cells = display_width(version) + 2U;
        const std::size_t gap = content_cells > display_width(left) + right_cells
                                    ? content_cells - display_width(left) - right_cells
                                    : 1U;
        output << vertical << theme.apply(left, TerminalStyle::Brand) << std::string(gap, ' ')
               << theme.apply(version, TerminalStyle::Metadata) << "  " << vertical << '\n';
        output << bottom_left << repeat(horizontal, layout.columns - 2U) << bottom_right << "\n\n";
    }
};

class HostRenderer final {
public:
    void render(const HostResult &host, std::ostream &output, const OutputContext &context,
                const TerminalLayout &layout, const TerminalCapabilities &terminal,
                const TerminalTheme &theme) const
    {
        std::string identity = sanitize_terminal_text(host.address);
        if (context.include_hostnames && host.hostname.has_value()) {
            identity += " (" + sanitize_terminal_text(*host.hostname) + ')';
        }
        std::string suffix = host_status(host);
        if (const auto latency = host_latency(host); latency.has_value()) {
            suffix += " / " + format_ms(*latency);
        }
        if (layout.mode == TerminalLayoutMode::Plain) {
            output << "Host " << ascii_safe(identity) << " - " << ascii_safe(suffix) << '\n';
            return;
        }
        const bool reachable = host_status(host) == "reachable";
        const std::string marker = terminal.unicode ? (reachable ? "●" : "○") : (reachable ? "+" : "-");
        const std::size_t reserved = 4U + display_width(suffix);
        const std::size_t identity_cells = layout.columns > reserved ? layout.columns - reserved : 16U;
        output << theme.apply(marker, reachable ? TerminalStyle::Open : TerminalStyle::Metadata) << ' '
               << theme.apply(fit(identity, identity_cells), TerminalStyle::Brand) << "  "
               << theme.apply(suffix, reachable ? TerminalStyle::Open : TerminalStyle::Warning) << '\n';
    }
};

class PortTableRenderer final {
public:
    void render(const HostResult &host, const std::vector<const portscan::PortResult *> &ports,
                std::ostream &output, const OutputContext &context, const TerminalLayout &layout,
                const TerminalCapabilities &terminal, const TerminalTheme &theme) const
    {
        const std::vector<const detect::ServiceResult *> services = detail::ordered_services(host);
        if (layout.mode == TerminalLayoutMode::Plain) {
            render_plain(ports, services, output, context);
            return;
        }
        if (ports.empty()) {
            output << "  " << theme.apply("No port rows matched the selected output filters.", TerminalStyle::Metadata)
                   << "\n";
            return;
        }
        output << '\n';
        if (layout.mode == TerminalLayoutMode::Wide) {
            render_wide(ports, services, output, context, layout, terminal, theme);
        } else if (layout.mode == TerminalLayoutMode::Medium) {
            render_medium(ports, services, output, context, layout, terminal, theme);
        } else {
            render_narrow(ports, services, output, context, layout, terminal, theme);
        }
    }

private:
    static void render_plain(const std::vector<const portscan::PortResult *> &ports,
                             const std::vector<const detect::ServiceResult *> &services,
                             std::ostream &output, const OutputContext &context)
    {
        if (ports.empty()) {
            output << "  No port rows matched the selected output filters.\n";
            return;
        }
        constexpr std::size_t endpoint_cells = 12U;
        constexpr std::size_t state_cells = 13U;
        constexpr std::size_t service_cells = 14U;
        constexpr std::size_t version_cells = 28U;
        output << "\n  " << padded("PORT", endpoint_cells) << padded("STATE", state_cells)
               << padded("SERVICE", service_cells)
               << padded("VERSION", version_cells + (context.include_reasons ? 1U : 0U));
        if (context.include_reasons) {
            output << "REASON";
        }
        output << "\n  " << std::string(context.include_reasons ? 90U : 67U, '-') << '\n';
        for (const portscan::PortResult *port : ports) {
            std::vector<const detect::ServiceResult *> matches = services_for(services, *port);
            if (matches.empty()) {
                matches.push_back(nullptr);
            }
            for (std::size_t index = 0U; index < matches.size(); ++index) {
                const detect::ServiceResult *service = matches[index];
                output << "  " << padded(index == 0U ? endpoint_label(*port) : "", endpoint_cells)
                       << padded(index == 0U ? portscan::port_state_name(port->state) : "", state_cells)
                       << padded(ascii_safe(service_label(service)), service_cells);
                const std::string version = ascii_safe(version_label(service, false));
                if (context.include_reasons) {
                    if (index == 0U) {
                        output << padded(version, version_cells) << ' ';
                        output << portscan::scan_reason_name(port->reason);
                    } else {
                        output << fit(version, version_cells);
                    }
                } else {
                    output << fit(version, version_cells);
                }
                output << '\n';
            }
        }
    }

    static void write_row(std::ostream &output, std::string_view endpoint, std::string_view state,
                          std::string_view service, std::string_view version, std::string_view reason,
                          std::size_t endpoint_cells, std::size_t state_cells, std::size_t service_cells,
                          std::size_t version_cells, std::size_t reason_cells, const TerminalTheme &theme,
                          TerminalStyle state_color)
    {
        output << "  " << padded(endpoint, endpoint_cells)
               << theme.apply(padded(state, state_cells), state_color);
        const bool has_version = version_cells > 0U && !version.empty();
        const bool has_reason = reason_cells > 0U && !reason.empty();
        output << (has_version || has_reason ? padded(service, service_cells) : fit(service, service_cells));
        if (version_cells > 0U) {
            output << (has_reason ? padded(version, version_cells) : fit(version, version_cells));
        }
        if (reason_cells > 0U) {
            output << fit(reason, reason_cells);
        }
        output << '\n';
    }

    static void render_wide(const std::vector<const portscan::PortResult *> &ports,
                            const std::vector<const detect::ServiceResult *> &services,
                            std::ostream &output, const OutputContext &context,
                            const TerminalLayout &layout, const TerminalCapabilities &terminal,
                            const TerminalTheme &theme)
    {
        constexpr std::size_t endpoint_cells = 11U;
        constexpr std::size_t state_cells = 14U;
        constexpr std::size_t service_cells = 18U;
        const std::size_t reason_cells = context.include_reasons ? 20U : 0U;
        const std::size_t fixed = 2U + endpoint_cells + state_cells + service_cells + reason_cells;
        const std::size_t version_cells = layout.columns > fixed ? layout.columns - fixed : 20U;
        write_row(output, "PORT", "STATE", "SERVICE", "VERSION", context.include_reasons ? "REASON" : "",
                  endpoint_cells, state_cells, service_cells, version_cells, reason_cells, theme, TerminalStyle::Brand);
        output << "  " << repeat(terminal.unicode ? "─" : "-", layout.columns - 2U) << '\n';
        for (const portscan::PortResult *port : ports) {
            std::vector<const detect::ServiceResult *> matches = services_for(services, *port);
            if (matches.empty()) {
                matches.push_back(nullptr);
            }
            for (std::size_t index = 0U; index < matches.size(); ++index) {
                const detect::ServiceResult *service = matches[index];
                write_row(output, index == 0U ? endpoint_label(*port) : "",
                          index == 0U ? portscan::port_state_name(port->state) : "",
                          service_label(service), version_label(service, terminal.unicode),
                          index == 0U && context.include_reasons ? portscan::scan_reason_name(port->reason) : "",
                          endpoint_cells, state_cells, service_cells, version_cells, reason_cells, theme,
                          state_style(port->state));
            }
        }
    }

    static void render_medium(const std::vector<const portscan::PortResult *> &ports,
                              const std::vector<const detect::ServiceResult *> &services,
                              std::ostream &output, const OutputContext &context,
                              const TerminalLayout &layout, const TerminalCapabilities &terminal,
                              const TerminalTheme &theme)
    {
        constexpr std::size_t endpoint_cells = 11U;
        constexpr std::size_t state_cells = 14U;
        constexpr std::size_t service_cells = 18U;
        const std::size_t version_cells = layout.columns - 2U - endpoint_cells - state_cells - service_cells;
        write_row(output, "PORT", "STATE", "SERVICE", "VERSION", "", endpoint_cells, state_cells,
                  service_cells, version_cells, 0U, theme, TerminalStyle::Brand);
        output << "  " << repeat(terminal.unicode ? "─" : "-", layout.columns - 2U) << '\n';
        for (const portscan::PortResult *port : ports) {
            std::vector<const detect::ServiceResult *> matches = services_for(services, *port);
            if (matches.empty()) {
                matches.push_back(nullptr);
            }
            for (std::size_t index = 0U; index < matches.size(); ++index) {
                const detect::ServiceResult *service = matches[index];
                write_row(output, index == 0U ? endpoint_label(*port) : "",
                          index == 0U ? portscan::port_state_name(port->state) : "",
                          service_label(service), version_label(service, terminal.unicode), "", endpoint_cells,
                          state_cells, service_cells, version_cells, 0U, theme, state_style(port->state));
            }
            if (context.include_reasons) {
                output << "    reason: " << fit(portscan::scan_reason_name(port->reason), layout.columns - 12U) << '\n';
            }
        }
    }

    static void render_narrow(const std::vector<const portscan::PortResult *> &ports,
                              const std::vector<const detect::ServiceResult *> &services,
                              std::ostream &output, const OutputContext &context,
                              const TerminalLayout &layout, const TerminalCapabilities &terminal,
                              const TerminalTheme &theme)
    {
        constexpr std::size_t endpoint_cells = 11U;
        constexpr std::size_t state_cells = 14U;
        const std::size_t service_cells = layout.columns - 2U - endpoint_cells - state_cells;
        write_row(output, "PORT", "STATE", "SERVICE", "", "", endpoint_cells, state_cells,
                  service_cells, 0U, 0U, theme, TerminalStyle::Brand);
        output << "  " << repeat(terminal.unicode ? "─" : "-", layout.columns - 2U) << '\n';
        for (const portscan::PortResult *port : ports) {
            std::vector<const detect::ServiceResult *> matches = services_for(services, *port);
            if (matches.empty()) {
                matches.push_back(nullptr);
            }
            for (std::size_t index = 0U; index < matches.size(); ++index) {
                const detect::ServiceResult *service = matches[index];
                write_row(output, index == 0U ? endpoint_label(*port) : "",
                          index == 0U ? portscan::port_state_name(port->state) : "",
                          service_label(service), "", "", endpoint_cells, state_cells, service_cells, 0U, 0U,
                          theme, state_style(port->state));
                const std::string version = version_label(service, terminal.unicode);
                if (version != "-") {
                    output << "    version: " << fit(version, layout.columns - 13U) << '\n';
                }
            }
            if (context.include_reasons) {
                output << "    reason: " << fit(portscan::scan_reason_name(port->reason), layout.columns - 12U) << '\n';
            }
        }
    }
};

class SummaryRenderer final {
public:
    void render(const ScanReport &report, std::ostream &output, const TerminalLayout &layout,
                const TerminalTheme &theme) const
    {
        const ScanSummary summary = calculate_summary(report);
        if (layout.mode == TerminalLayoutMode::Plain) {
            output << "Summary: " << summary.hosts << " hosts (" << summary.hosts_up << " up); "
                   << summary.ports_scanned << " ports scanned; " << summary.open_ports << " open, "
                   << summary.closed_ports << " closed, " << summary.filtered_ports << " filtered; "
                   << summary.services_detected << " services";
            if (report.duration_ms.has_value()) {
                output << " duration=" << format_ms(*report.duration_ms);
            }
            output << '\n';
            return;
        }
        output << '\n' << theme.apply("Scan complete", TerminalStyle::Success);
        if (report.duration_ms.has_value()) {
            output << "  " << theme.apply(format_ms(*report.duration_ms), TerminalStyle::Metadata);
        }
        const std::string open = std::to_string(summary.open_ports) + " open";
        const std::string closed = std::to_string(summary.closed_ports) + " closed";
        const std::string filtered = std::to_string(summary.filtered_ports) + " filtered";
        const std::string remainder = std::to_string(summary.ports_scanned) + " scanned / " +
                                      std::to_string(summary.services_detected) + " services";
        const std::string complete = open + " / " + closed + " / " + filtered + " / " + remainder;
        if (display_width(complete) + 2U > layout.columns) {
            output << "\n  " << theme.apply(fit(complete, layout.columns - 2U), TerminalStyle::Metadata) << '\n';
        } else {
            output << '\n' << "  " << theme.apply(open, TerminalStyle::Open)
                   << " / " << theme.apply(closed, TerminalStyle::Closed)
                   << " / " << theme.apply(filtered, TerminalStyle::Filtered)
                   << " / " << remainder << '\n';
        }
    }
};

class FooterRenderer final {
public:
    void render(std::ostream &output, const TerminalLayout &layout, const TerminalCapabilities &terminal,
                const TerminalTheme &theme) const
    {
        if (layout.mode == TerminalLayoutMode::Plain) {
            return;
        }
        const std::string footer = terminal.unicode ? "Skan — See more. Know more. Secure more."
                                                    : "Skan - See more. Know more. Secure more.";
        output << '\n' << theme.apply(fit(footer, layout.columns), TerminalStyle::Brand) << '\n';
    }
};

void render_os(const HostResult &host, std::ostream &output, const TerminalLayout &layout,
               const TerminalTheme &theme)
{
    if (!host.os_detection.has_value()) {
        return;
    }
    const auto &detection = *host.os_detection;
    std::string label = detection.vendor;
    if (!detection.family.empty()) {
        label += (label.empty() ? "" : " ") + detection.family;
    }
    if (!detection.generation.empty()) {
        label += " " + detection.generation;
    }
    if (!host.os_matches.empty()) {
        const auto matches = detail::ordered_os_matches(host);
        if (!matches.front()->fingerprint_name.empty()) {
            label += " / " + matches.front()->fingerprint_name;
        }
    }
    label += " / " + std::to_string(static_cast<int>(std::lround(detection.confidence * 100.0))) + "%";
    if (layout.mode == TerminalLayoutMode::Plain) {
        output << "OS: " << ascii_safe(label) << '\n';
    } else {
        output << "  " << theme.apply("OS", TerminalStyle::Brand) << "  "
               << fit(label, layout.columns - 6U) << '\n';
    }
}

void render_messages(std::ostream &output, const std::vector<std::string> &messages, std::string_view label,
                     TerminalStyle style, const TerminalLayout &layout,
                     const TerminalCapabilities &terminal, const TerminalTheme &theme)
{
    const std::string marker = terminal.unicode && style == TerminalStyle::Closed ? "×" : "!";
    for (const std::string &message : messages) {
        if (layout.mode == TerminalLayoutMode::Plain) {
            output << label << ": " << ascii_safe(message) << '\n';
        } else {
            output << "  " << theme.apply(marker, style) << ' ' << fit(message, layout.columns - 4U) << '\n';
        }
    }
}

} // namespace

OutputStatus TerminalReportRenderer::render(const ScanReport &report, std::ostream &output,
                                            const OutputContext &context) const
{
    if (validate_report(report) != OutputStatus::Ok) {
        return OutputStatus::InvalidReport;
    }
    const TerminalLayout layout = choose_terminal_layout(context.terminal);
    const TerminalTheme theme(context.terminal.color && layout.mode != TerminalLayoutMode::Plain);
    HeaderRenderer{}.render(report, output, layout, context.terminal, theme);
    if (report.target_spec.has_value()) {
        if (layout.mode == TerminalLayoutMode::Plain) {
            output << "Target  " << ascii_safe(*report.target_spec) << "\n\n";
        } else {
            output << theme.apply("Target", TerminalStyle::Metadata) << "  "
                   << theme.apply(fit(*report.target_spec, layout.columns - 8U), TerminalStyle::Brand) << "\n\n";
        }
    }
    for (const HostResult *host : detail::ordered_hosts(report)) {
        HostRenderer{}.render(*host, output, context, layout, context.terminal, theme);
        PortTableRenderer{}.render(*host, detail::ordered_ports(*host, context), output, context, layout,
                                   context.terminal, theme);
        render_os(*host, output, layout, theme);
        render_messages(output, host->warnings, "Warning", TerminalStyle::Warning, layout, context.terminal, theme);
        render_messages(output, host->errors, "Error", TerminalStyle::Closed, layout, context.terminal, theme);
        output << '\n';
    }
    SummaryRenderer{}.render(report, output, layout, theme);
    render_messages(output, report.warnings, "Warning", TerminalStyle::Warning, layout, context.terminal, theme);
    render_messages(output, report.errors, "Error", TerminalStyle::Closed, layout, context.terminal, theme);
    FooterRenderer{}.render(output, layout, context.terminal, theme);
    return detail::check_stream(output);
}

} // namespace skan::output
