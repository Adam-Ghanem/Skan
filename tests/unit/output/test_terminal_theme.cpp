#include <cassert>
#include <string>

#include "output/terminal_text.hpp"
#include "output/terminal_theme.hpp"

int main()
{
    using skan::output::TerminalStyle;
    using skan::output::TerminalTheme;
    using skan::output::display_width;

    const TerminalTheme plain(false);
    assert(plain.apply("OPEN", TerminalStyle::Open) == "OPEN");
    assert(plain.apply(std::string("unsafe") + '\x1b', TerminalStyle::Warning) == "unsafe?");

    const TerminalTheme colored(true);
    const std::string open = colored.apply("OPEN", TerminalStyle::Open);
    assert(open == "\x1b[32mOPEN\x1b[0m");
    assert(display_width(open) == 4U);
    assert(colored.apply("brand", TerminalStyle::Brand) == "\x1b[36;1mbrand\x1b[0m");
    assert(colored.apply("meta", TerminalStyle::Metadata) == "\x1b[2mmeta\x1b[0m");
    assert(colored.apply("filtered", TerminalStyle::Filtered) == "\x1b[33mfiltered\x1b[0m");
    assert(colored.apply("closed", TerminalStyle::Closed) == "\x1b[31mclosed\x1b[0m");
    assert(colored.apply("warning", TerminalStyle::Warning) == "\x1b[33;1mwarning\x1b[0m");
    assert(colored.apply("success", TerminalStyle::Success) == "\x1b[32;1msuccess\x1b[0m");

    return 0;
}
