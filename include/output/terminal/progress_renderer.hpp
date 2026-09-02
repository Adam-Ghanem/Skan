#ifndef SKAN_OUTPUT_TERMINAL_PROGRESS_RENDERER_HPP
#define SKAN_OUTPUT_TERMINAL_PROGRESS_RENDERER_HPP

#include <cstddef>
#include <iosfwd>
#include <string_view>

#include "orchestrator/scan_events.hpp"
#include "output/result_model.hpp"
#include "output/terminal_capabilities.hpp"

namespace skan::output {

struct ProgressPolicyInput final {
    TerminalCapabilities standard_output;
    TerminalCapabilities standard_error;
    OutputFormat output_format{OutputFormat::Normal};
    bool writes_output_file{false};
    bool debug_logging{false};
};

bool progress_allowed(const ProgressPolicyInput &input) noexcept;

class TerminalProgressRenderer final {
public:
    TerminalProgressRenderer(std::ostream &output, bool enabled, bool unicode) noexcept;
    ~TerminalProgressRenderer();

    void handle(const orchestrator::ScanEvent &event);
    void clear();

private:
    void status(std::string_view message);

    std::ostream &output_;
    bool enabled_{false};
    bool unicode_{false};
    bool active_line_{false};
    std::size_t hosts_observed_{0U};
    std::size_t tcp_ports_completed_{0U};
    std::size_t udp_ports_completed_{0U};
    std::size_t services_detected_{0U};
};

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_PROGRESS_RENDERER_HPP
