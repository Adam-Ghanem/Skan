#ifndef SKAN_OUTPUT_TERMINAL_TEXT_HPP
#define SKAN_OUTPUT_TERMINAL_TEXT_HPP

#include <cstddef>
#include <string>
#include <string_view>

namespace skan::output {

std::string sanitize_terminal_text(std::string_view text);
std::size_t display_width(std::string_view text) noexcept;
std::string truncate_display(std::string_view text, std::size_t maximum_cells);

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_TEXT_HPP
