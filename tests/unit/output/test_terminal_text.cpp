#include <cassert>
#include <cstddef>
#include <string>

#include "output/terminal_text.hpp"

int main()
{
    using skan::output::display_width;
    using skan::output::sanitize_terminal_text;
    using skan::output::sanitize_utf8_text;
    using skan::output::truncate_display;

    const std::string hostile =
        std::string("safe") + '\x1b' + "[31m" + '\a' + '\r' + '\n' + '\t' +
        static_cast<char>(0x9b) + static_cast<char>(0x9d) + static_cast<char>(0x9c) +
        "end";
    const std::string sanitized = sanitize_terminal_text(hostile);
    assert(sanitized.find('\x1b') == std::string::npos);
    assert(sanitized.find('\a') == std::string::npos);
    assert(sanitized.find('\r') == std::string::npos);
    assert(sanitized.find('\n') == std::string::npos);
    assert(sanitized.find('\t') == std::string::npos);
    assert(sanitized.find(static_cast<char>(0x9b)) == std::string::npos);

    const std::string malformed = std::string("A") + static_cast<char>(0xc3) + "(";
    assert(sanitize_terminal_text(malformed) == "A?(");
    assert(sanitize_utf8_text(malformed) == "A?(");
    assert(sanitize_utf8_text("line\n\tcaf\xc3\xa9") == "line\n\tcaf\xc3\xa9");

    const std::string bidi_override{"before\xe2\x80\xae" "after"};
    assert(sanitize_terminal_text(bidi_override) == "before?after");

    assert(display_width("\x1b[32mOPEN\x1b[0m") == 4U);
    assert(display_width("caf\xc3\xa9") == 4U);
    assert(display_width("e\xcc\x81") == 1U);
    assert(display_width("\xe7\x95\x8c") == 2U);
    assert(display_width("\xf0\x9f\x94\x8d") == 2U);

    assert(truncate_display("abcdef", 5U) == "ab...");
    assert(truncate_display("\xe7\x95\x8c\xe7\x95\x8c", 3U) == "...");
    assert(truncate_display("\xe7\x95\x8c\xe7\x95\x8c", 4U) == "\xe7\x95\x8c\xe7\x95\x8c");
    assert(display_width(truncate_display("service-\xe7\x95\x8c-long", 10U)) <= 10U);
    assert(truncate_display("ignored", 0U).empty());

    std::string combining_flood{"a"};
    for (std::size_t index = 0U; index < 4096U; ++index) {
        combining_flood += "\xcc\x81";
    }
    const std::string bounded = truncate_display(combining_flood, 10U);
    assert(bounded.size() <= 40U);
    assert(bounded.ends_with("..."));

    return 0;
}
