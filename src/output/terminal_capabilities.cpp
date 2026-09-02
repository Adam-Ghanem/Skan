#include "output/terminal_capabilities.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <string>
#include <string_view>

#include <sys/ioctl.h>
#include <unistd.h>

namespace skan::output {
namespace {

constexpr std::size_t kDefaultColumns = 80U;
constexpr std::size_t kMaximumColumns = 300U;

bool is_utf8_locale(std::string locale)
{
    std::transform(locale.begin(), locale.end(), locale.begin(), [](unsigned char value) {
        if (value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('Z')) {
            return static_cast<char>(value - static_cast<unsigned char>('A') + static_cast<unsigned char>('a'));
        }
        return static_cast<char>(value);
    });
    return locale.find("utf-8") != std::string::npos || locale.find("utf8") != std::string::npos;
}

std::string environment_value(const char *name)
{
    const char *value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
}

std::string configured_locale()
{
    for (const char *name : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        std::string value = environment_value(name);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

std::size_t parse_columns(std::string_view value) noexcept
{
    if (value.empty()) {
        return 0U;
    }
    std::size_t parsed = 0U;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        return 0U;
    }
    return parsed;
}

std::size_t terminal_columns(int file_descriptor) noexcept
{
    winsize size{};
    if (::ioctl(file_descriptor, TIOCGWINSZ, &size) == 0 && size.ws_col > 0U) {
        return static_cast<std::size_t>(size.ws_col);
    }
    return parse_columns(environment_value("COLUMNS"));
}

} // namespace

TerminalCapabilities evaluate_terminal_capabilities(const TerminalDetectionInput &input) noexcept
{
    TerminalCapabilities capabilities;
    capabilities.columns = input.columns == 0U
                               ? kDefaultColumns
                               : std::min(input.columns, kMaximumColumns);
    capabilities.interactive = input.interactive && input.term != "dumb";
    capabilities.color = capabilities.interactive && !input.no_color_environment && !input.no_color_requested;
    capabilities.unicode = capabilities.interactive && is_utf8_locale(input.locale);
    return capabilities;
}

TerminalCapabilities detect_terminal_capabilities(int file_descriptor, bool no_color_requested) noexcept
{
    TerminalDetectionInput input;
    input.interactive = ::isatty(file_descriptor) != 0;
    input.columns = terminal_columns(file_descriptor);
    input.term = environment_value("TERM");
    input.locale = configured_locale();
    const char *no_color = std::getenv("NO_COLOR");
    input.no_color_environment = no_color != nullptr && *no_color != '\0';
    input.no_color_requested = no_color_requested;
    return evaluate_terminal_capabilities(input);
}

} // namespace skan::output
