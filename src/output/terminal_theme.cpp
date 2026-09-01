#include "output/terminal_theme.hpp"

#include "output/terminal_text.hpp"

namespace skan::output {
namespace {

constexpr std::string_view kReset{"\x1b[0m"};

std::string_view style_token(TerminalStyle style) noexcept
{
    switch (style) {
    case TerminalStyle::Brand:
        return "\x1b[36;1m";
    case TerminalStyle::Metadata:
        return "\x1b[2m";
    case TerminalStyle::Open:
        return "\x1b[32m";
    case TerminalStyle::Filtered:
        return "\x1b[33m";
    case TerminalStyle::Closed:
        return "\x1b[31m";
    case TerminalStyle::Warning:
        return "\x1b[33;1m";
    case TerminalStyle::Success:
        return "\x1b[32;1m";
    }
    return {};
}

} // namespace

TerminalTheme::TerminalTheme(bool color_enabled) noexcept
    : color_enabled_(color_enabled)
{
}

std::string TerminalTheme::apply(std::string_view text, TerminalStyle style) const
{
    const std::string sanitized = sanitize_terminal_text(text);
    if (!color_enabled_) {
        return sanitized;
    }
    return std::string(style_token(style)) + sanitized + std::string(kReset);
}

} // namespace skan::output
