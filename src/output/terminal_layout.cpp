#include "output/terminal_layout.hpp"

namespace skan::output {

TerminalLayout choose_terminal_layout(const TerminalCapabilities &capabilities) noexcept
{
    TerminalLayout layout;
    layout.columns = capabilities.columns;
    if (!capabilities.interactive || capabilities.columns < 64U) {
        layout.mode = TerminalLayoutMode::Plain;
    } else if (capabilities.columns < 88U) {
        layout.mode = TerminalLayoutMode::Narrow;
    } else if (capabilities.columns < 120U) {
        layout.mode = TerminalLayoutMode::Medium;
    } else {
        layout.mode = TerminalLayoutMode::Wide;
    }
    return layout;
}

} // namespace skan::output
