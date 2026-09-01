#include "output/terminal_text.hpp"

#include <algorithm>
#include <cstdint>

namespace skan::output {
namespace {

struct DecodedCodePoint final {
    char32_t value{U'?'};
    std::size_t length{1U};
    bool valid{false};
};

bool continuation(unsigned char value) noexcept
{
    return (value & 0xc0U) == 0x80U;
}

DecodedCodePoint decode(std::string_view text, std::size_t offset) noexcept
{
    const auto byte = [&](std::size_t index) {
        return static_cast<unsigned char>(text[offset + index]);
    };
    const std::size_t remaining = text.size() - offset;
    const unsigned char first = byte(0U);
    if (first <= 0x7fU) {
        return {static_cast<char32_t>(first), 1U, true};
    }
    if (first >= 0xc2U && first <= 0xdfU && remaining >= 2U && continuation(byte(1U))) {
        const char32_t value = static_cast<char32_t>(((first & 0x1fU) << 6U) | (byte(1U) & 0x3fU));
        return {value, 2U, true};
    }
    if (first >= 0xe0U && first <= 0xefU && remaining >= 3U && continuation(byte(1U)) &&
        continuation(byte(2U))) {
        const unsigned char second = byte(1U);
        if ((first == 0xe0U && second < 0xa0U) || (first == 0xedU && second >= 0xa0U)) {
            return {};
        }
        const char32_t value = static_cast<char32_t>(((first & 0x0fU) << 12U) |
                                                     ((second & 0x3fU) << 6U) |
                                                     (byte(2U) & 0x3fU));
        return {value, 3U, true};
    }
    if (first >= 0xf0U && first <= 0xf4U && remaining >= 4U && continuation(byte(1U)) &&
        continuation(byte(2U)) && continuation(byte(3U))) {
        const unsigned char second = byte(1U);
        if ((first == 0xf0U && second < 0x90U) || (first == 0xf4U && second >= 0x90U)) {
            return {};
        }
        const char32_t value = static_cast<char32_t>(((first & 0x07U) << 18U) |
                                                     ((second & 0x3fU) << 12U) |
                                                     ((byte(2U) & 0x3fU) << 6U) |
                                                     (byte(3U) & 0x3fU));
        return {value, 4U, true};
    }
    return {};
}

bool terminal_control(char32_t value) noexcept
{
    return value <= U'\x1f' || (value >= U'\x7f' && value <= U'\x9f') ||
           value == U'\u061c' || value == U'\u200e' || value == U'\u200f' ||
           (value >= U'\u202a' && value <= U'\u202e') ||
           (value >= U'\u2066' && value <= U'\u2069') || value == U'\ufeff';
}

bool combining(char32_t value) noexcept
{
    return (value >= U'\u0300' && value <= U'\u036f') ||
           (value >= U'\u1ab0' && value <= U'\u1aff') ||
           (value >= U'\u1dc0' && value <= U'\u1dff') ||
           (value >= U'\u20d0' && value <= U'\u20ff') ||
           (value >= U'\ufe00' && value <= U'\ufe0f') ||
           (value >= U'\ufe20' && value <= U'\ufe2f') || value == U'\u200d' ||
           (value >= U'\U0001f3fb' && value <= U'\U0001f3ff');
}

bool wide(char32_t value) noexcept
{
    return (value >= U'\u1100' && value <= U'\u115f') || value == U'\u2329' ||
           value == U'\u232a' || (value >= U'\u2e80' && value <= U'\ua4cf') ||
           (value >= U'\uac00' && value <= U'\ud7a3') ||
           (value >= U'\uf900' && value <= U'\ufaff') ||
           (value >= U'\ufe10' && value <= U'\ufe19') ||
           (value >= U'\ufe30' && value <= U'\ufe6f') ||
           (value >= U'\uff00' && value <= U'\uff60') ||
           (value >= U'\uffe0' && value <= U'\uffe6') ||
           (value >= U'\U0001f300' && value <= U'\U0001faff') ||
           (value >= U'\U00020000' && value <= U'\U0003fffd');
}

std::size_t code_point_width(const DecodedCodePoint &decoded) noexcept
{
    if (!decoded.valid || terminal_control(decoded.value)) {
        return 1U;
    }
    if (combining(decoded.value)) {
        return 0U;
    }
    return wide(decoded.value) ? 2U : 1U;
}

std::size_t sgr_length(std::string_view text, std::size_t offset) noexcept
{
    if (offset + 2U >= text.size() || text[offset] != '\x1b' || text[offset + 1U] != '[') {
        return 0U;
    }
    std::size_t cursor = offset + 2U;
    while (cursor < text.size()) {
        const unsigned char value = static_cast<unsigned char>(text[cursor]);
        if (value == static_cast<unsigned char>('m')) {
            return cursor - offset + 1U;
        }
        if ((value < static_cast<unsigned char>('0') || value > static_cast<unsigned char>('9')) &&
            value != static_cast<unsigned char>(';')) {
            return 0U;
        }
        ++cursor;
    }
    return 0U;
}

} // namespace

std::string sanitize_utf8_text(std::string_view text)
{
    std::string sanitized;
    sanitized.reserve(text.size());
    for (std::size_t offset = 0U; offset < text.size();) {
        const DecodedCodePoint decoded = decode(text, offset);
        if (!decoded.valid) {
            sanitized.push_back('?');
            ++offset;
            continue;
        }
        sanitized.append(text.substr(offset, decoded.length));
        offset += decoded.length;
    }
    return sanitized;
}

std::string sanitize_terminal_text(std::string_view text)
{
    std::string sanitized;
    sanitized.reserve(text.size());
    for (std::size_t offset = 0U; offset < text.size();) {
        const DecodedCodePoint decoded = decode(text, offset);
        if (!decoded.valid || terminal_control(decoded.value)) {
            sanitized.push_back('?');
            offset += decoded.valid ? decoded.length : 1U;
            continue;
        }
        sanitized.append(text.substr(offset, decoded.length));
        offset += decoded.length;
    }
    return sanitized;
}

std::size_t display_width(std::string_view text) noexcept
{
    std::size_t cells = 0U;
    for (std::size_t offset = 0U; offset < text.size();) {
        const std::size_t escape_length = sgr_length(text, offset);
        if (escape_length > 0U) {
            offset += escape_length;
            continue;
        }
        const DecodedCodePoint decoded = decode(text, offset);
        cells += code_point_width(decoded);
        offset += decoded.valid ? decoded.length : 1U;
    }
    return cells;
}

std::string truncate_display(std::string_view text, std::size_t maximum_cells)
{
    if (maximum_cells == 0U) {
        return {};
    }
    const std::string sanitized = sanitize_terminal_text(text);
    if (display_width(sanitized) <= maximum_cells) {
        return sanitized;
    }
    if (maximum_cells <= 3U) {
        return std::string(maximum_cells, '.');
    }

    const std::size_t content_cells = maximum_cells - 3U;
    std::size_t used = 0U;
    std::string truncated;
    truncated.reserve(std::min(sanitized.size(), maximum_cells));
    for (std::size_t offset = 0U; offset < sanitized.size();) {
        const DecodedCodePoint decoded = decode(sanitized, offset);
        const std::size_t width = code_point_width(decoded);
        if (used + width > content_cells) {
            break;
        }
        truncated.append(sanitized.substr(offset, decoded.length));
        used += width;
        offset += decoded.length;
    }
    truncated.append("...");
    return truncated;
}

} // namespace skan::output
