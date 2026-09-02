#include "output/terminal_text.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

#include "core/text_safety.hpp"

namespace skan::output {
namespace {

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

std::size_t code_point_width(const core::text::DecodedCodePoint &decoded) noexcept
{
    if (!decoded.valid || core::text::terminal_control(decoded.value)) {
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
    return core::text::sanitize_utf8(text);
}

std::string sanitize_xml_text(std::string_view text)
{
    return core::text::sanitize_xml_1_0(text);
}

std::string sanitize_terminal_text(std::string_view text)
{
    return core::text::sanitize_terminal(text);
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
        const core::text::DecodedCodePoint decoded = core::text::decode_utf8(text, offset);
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
    const std::size_t maximum_bytes =
        maximum_cells > std::numeric_limits<std::size_t>::max() / 4U
            ? std::numeric_limits<std::size_t>::max()
            : maximum_cells * 4U;
    if (display_width(sanitized) <= maximum_cells && sanitized.size() <= maximum_bytes) {
        return sanitized;
    }
    if (maximum_cells <= 3U) {
        return std::string(maximum_cells, '.');
    }

    const std::size_t content_cells = maximum_cells - 3U;
    const std::size_t content_bytes = maximum_bytes - 3U;
    std::size_t used = 0U;
    std::string truncated;
    truncated.reserve(std::min(sanitized.size(), maximum_cells));
    for (std::size_t offset = 0U; offset < sanitized.size();) {
        const core::text::DecodedCodePoint decoded = core::text::decode_utf8(sanitized, offset);
        const std::size_t width = code_point_width(decoded);
        if (used + width > content_cells || decoded.length > content_bytes - truncated.size()) {
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
