#ifndef SKAN_OUTPUT_TERMINAL_CAPABILITIES_HPP
#define SKAN_OUTPUT_TERMINAL_CAPABILITIES_HPP

#include <cstddef>
#include <string>

namespace skan::output {

struct TerminalDetectionInput final {
    bool interactive{false};
    std::size_t columns{0U};
    std::string term;
    std::string locale;
    bool no_color_environment{false};
    bool no_color_requested{false};
};

struct TerminalCapabilities final {
    bool interactive{false};
    std::size_t columns{80U};
    bool color{false};
    bool unicode{false};
};

TerminalCapabilities evaluate_terminal_capabilities(const TerminalDetectionInput &input) noexcept;
TerminalCapabilities detect_terminal_capabilities(int file_descriptor, bool no_color_requested) noexcept;

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_CAPABILITIES_HPP
