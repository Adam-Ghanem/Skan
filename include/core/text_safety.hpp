#ifndef SKAN_CORE_TEXT_SAFETY_HPP
#define SKAN_CORE_TEXT_SAFETY_HPP

#include <cstddef>
#include <string>
#include <string_view>

namespace skan::core::text {

struct DecodedCodePoint final {
    char32_t value{U'?'};
    std::size_t length{1U};
    bool valid{false};
};

DecodedCodePoint decode_utf8(std::string_view text, std::size_t offset) noexcept;
bool terminal_control(char32_t value) noexcept;
bool xml_1_0_character(char32_t value) noexcept;

std::string sanitize_utf8(std::string_view text);
std::string sanitize_terminal(std::string_view text);
std::string sanitize_xml_1_0(std::string_view text);

} // namespace skan::core::text

#endif // SKAN_CORE_TEXT_SAFETY_HPP
