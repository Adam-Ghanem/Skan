#include "output/terminal/progress_renderer.hpp"

#include <ostream>
#include <string>

#include "output/terminal_text.hpp"

namespace skan::output {

bool progress_allowed(const ProgressPolicyInput &input) noexcept
{
    return input.standard_output.interactive && input.standard_error.interactive &&
           input.output_format == OutputFormat::Normal && !input.writes_output_file &&
           !input.debug_logging;
}

TerminalProgressRenderer::TerminalProgressRenderer(
    std::ostream &output,
    bool enabled,
    bool unicode) noexcept
    : output_(output), enabled_(enabled), unicode_(unicode)
{
}

TerminalProgressRenderer::~TerminalProgressRenderer()
{
    try {
        clear();
    } catch (...) {
        // Terminal cleanup is presentation-only and cannot safely escape a destructor.
    }
}

void TerminalProgressRenderer::status(std::string_view message)
{
    if (!enabled_) {
        return;
    }
    output_ << "\r\x1b[2K" << (unicode_ ? "◆ " : "* ")
            << sanitize_terminal_text(message) << std::flush;
    active_line_ = true;
}

void TerminalProgressRenderer::clear()
{
    if (enabled_ && active_line_) {
        output_ << "\r\x1b[2K" << std::flush;
        active_line_ = false;
    }
}

void TerminalProgressRenderer::handle(const orchestrator::ScanEvent &event)
{
    if (!enabled_) {
        return;
    }
    switch (event.type) {
    case orchestrator::ScanEventType::ScanStarted:
        break;
    case orchestrator::ScanEventType::StageStarted:
        clear();
        break;
    case orchestrator::ScanEventType::HostDiscovered:
        ++hosts_observed_;
        if (hosts_observed_ == 1U || hosts_observed_ % 64U == 0U) {
            status("Discovery: " + std::to_string(hosts_observed_) + " hosts checked");
        }
        break;
    case orchestrator::ScanEventType::PortCompleted:
        if (event.stage == orchestrator::StageKind::UdpScan) {
            ++udp_ports_completed_;
            if (udp_ports_completed_ == 1U || udp_ports_completed_ % 64U == 0U) {
                status("UDP scan: " + std::to_string(udp_ports_completed_) + " port results completed");
            }
        } else {
            ++tcp_ports_completed_;
            if (tcp_ports_completed_ == 1U || tcp_ports_completed_ % 64U == 0U) {
                status("Port scan: " + std::to_string(tcp_ports_completed_) + " port results completed");
            }
        }
        break;
    case orchestrator::ScanEventType::ServiceDetected:
        ++services_detected_;
        if (services_detected_ == 1U || services_detected_ % 64U == 0U) {
            status("Service detection: " + std::to_string(services_detected_) + " results completed");
        }
        break;
    case orchestrator::ScanEventType::OSDetectionCompleted:
        status("OS detection completed");
        break;
    case orchestrator::ScanEventType::StageCompleted:
        if (event.stage == orchestrator::StageKind::Discovery) {
            status("Discovery: " + std::to_string(hosts_observed_) + " hosts checked");
        } else if (event.stage == orchestrator::StageKind::PortScan) {
            status("Port scan: " + std::to_string(tcp_ports_completed_) + " port results completed");
        } else if (event.stage == orchestrator::StageKind::UdpScan) {
            status("UDP scan: " + std::to_string(udp_ports_completed_) + " port results completed");
        } else if (event.stage == orchestrator::StageKind::ServiceDetection) {
            status("Service detection: " + std::to_string(services_detected_) + " results completed");
        } else if (event.stage == orchestrator::StageKind::OSDetection) {
            status("OS detection completed");
        }
        break;
    case orchestrator::ScanEventType::ScanCompleted:
    case orchestrator::ScanEventType::ScanFailed:
    case orchestrator::ScanEventType::ScanCancelled:
        clear();
        break;
    }
}

} // namespace skan::output
