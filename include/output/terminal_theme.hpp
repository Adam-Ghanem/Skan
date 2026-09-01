#ifndef SKAN_OUTPUT_TERMINAL_THEME_HPP
#define SKAN_OUTPUT_TERMINAL_THEME_HPP

#include <string>
#include <string_view>

namespace skan::output {

enum class TerminalStyle {
    Brand,
    Metadata,
    Open,
    Filtered,
    Closed,
    Warning,
    Success,
};

class TerminalTheme final {
public:
    explicit TerminalTheme(bool color_enabled) noexcept;

    std::string apply(std::string_view text, TerminalStyle style) const;

private:
    bool color_enabled_{false};
};

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_THEME_HPP
