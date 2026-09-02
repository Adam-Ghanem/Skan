#include <array>
#include <cassert>
#include <cstddef>

#include "output/terminal_layout.hpp"

int main()
{
    using skan::output::TerminalCapabilities;
    using skan::output::TerminalLayoutMode;
    using skan::output::choose_terminal_layout;

    struct Case final {
        std::size_t columns;
        TerminalLayoutMode expected;
    };

    constexpr std::array<Case, 7U> cases{{
        {63U, TerminalLayoutMode::Plain},
        {64U, TerminalLayoutMode::Narrow},
        {87U, TerminalLayoutMode::Narrow},
        {88U, TerminalLayoutMode::Medium},
        {119U, TerminalLayoutMode::Medium},
        {120U, TerminalLayoutMode::Wide},
        {300U, TerminalLayoutMode::Wide},
    }};

    for (const Case &test_case : cases) {
        TerminalCapabilities capabilities;
        capabilities.interactive = true;
        capabilities.columns = test_case.columns;
        capabilities.color = true;
        capabilities.unicode = true;
        const auto layout = choose_terminal_layout(capabilities);
        assert(layout.mode == test_case.expected);
        assert(layout.columns == test_case.columns);
    }

    TerminalCapabilities redirected;
    redirected.interactive = false;
    redirected.columns = 200U;
    const auto plain = choose_terminal_layout(redirected);
    assert(plain.mode == TerminalLayoutMode::Plain);
    assert(plain.columns == 200U);

    return 0;
}
