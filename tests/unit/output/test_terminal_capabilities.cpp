#include <cassert>
#include <cstddef>

#include "output/terminal_capabilities.hpp"

int main()
{
    using skan::output::TerminalDetectionInput;
    using skan::output::evaluate_terminal_capabilities;

    TerminalDetectionInput input;
    input.interactive = true;
    input.columns = 120U;
    input.term = "xterm-256color";
    input.locale = "C.UTF-8";

    const auto capable = evaluate_terminal_capabilities(input);
    assert(capable.interactive);
    assert(capable.columns == 120U);
    assert(capable.color);
    assert(capable.unicode);

    input.interactive = false;
    const auto redirected = evaluate_terminal_capabilities(input);
    assert(!redirected.interactive);
    assert(!redirected.color);
    assert(!redirected.unicode);

    input.interactive = true;
    input.term = "dumb";
    const auto dumb = evaluate_terminal_capabilities(input);
    assert(!dumb.interactive);
    assert(!dumb.color);
    assert(!dumb.unicode);

    input.term = "xterm-256color";
    input.no_color_environment = true;
    const auto no_color_environment = evaluate_terminal_capabilities(input);
    assert(no_color_environment.interactive);
    assert(!no_color_environment.color);
    assert(no_color_environment.unicode);

    input.no_color_environment = false;
    input.no_color_requested = true;
    const auto no_color_requested = evaluate_terminal_capabilities(input);
    assert(!no_color_requested.color);
    assert(no_color_requested.unicode);

    input.no_color_requested = false;
    input.locale = "C";
    const auto ascii_locale = evaluate_terminal_capabilities(input);
    assert(ascii_locale.color);
    assert(!ascii_locale.unicode);

    input.locale = "en_US.utf8";
    const auto utf8_locale = evaluate_terminal_capabilities(input);
    assert(utf8_locale.unicode);

    input.columns = 0U;
    const auto missing_width = evaluate_terminal_capabilities(input);
    assert(missing_width.columns == 80U);

    input.columns = 10000U;
    const auto excessive_width = evaluate_terminal_capabilities(input);
    assert(excessive_width.columns == 300U);

    return 0;
}
