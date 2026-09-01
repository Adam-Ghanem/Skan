#ifndef SKAN_OUTPUT_TERMINAL_LAYOUT_HPP
#define SKAN_OUTPUT_TERMINAL_LAYOUT_HPP

#include <cstddef>

#include "output/terminal_capabilities.hpp"

namespace skan::output {

enum class TerminalLayoutMode {
    Plain,
    Narrow,
    Medium,
    Wide,
};

struct TerminalLayout final {
    TerminalLayoutMode mode{TerminalLayoutMode::Plain};
    std::size_t columns{80U};
};

TerminalLayout choose_terminal_layout(const TerminalCapabilities &capabilities) noexcept;

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_LAYOUT_HPP
