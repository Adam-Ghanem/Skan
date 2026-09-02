#include "core/text_safety.hpp"

namespace skan::core::text {
namespace {

bool continuation(unsigned char value) noexcept
{
    return (value & 0xc0U) == 0x80U;
}

template <typename Allowed>
std::string sanitize(std::string_view text, Allowed allowed)
{
    std::string sanitized;
    sanitized.reserve(text.size());
    for (std::size_t offset = 0U; offset < text.size();) {
        const DecodedCodePoint decoded = decode_utf8(text, offset);
        if (!decoded.valid || !allowed(decoded.value)) {
            sanitized.push_back('?');
            offset += decoded.valid ? decoded.length : 1U;
            continue;
        }
        sanitized.append(text.substr(offset, decoded.length));
        offset += decoded.length;
    }
    return sanitized;
}

} // namespace

DecodedCodePoint decode_utf8(std::string_view text, std::size_t offset) noexcept
{
    if (offset >= text.size()) {
        return {};
    }
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

bool xml_1_0_character(char32_t value) noexcept
{
    return value == U'\t' || value == U'\n' || value == U'\r' ||
           (value >= U'\x20' && value <= U'\ud7ff') ||
           (value >= U'\ue000' && value <= U'\ufffd') ||
           (value >= U'\U00010000' && value <= U'\U0010ffff');
}

std::string sanitize_utf8(std::string_view text)
{
    return sanitize(text, [](char32_t) { return true; });
}

std::string sanitize_terminal(std::string_view text)
{
    return sanitize(text, [](char32_t value) { return !terminal_control(value); });
}

std::string sanitize_xml_1_0(std::string_view text)
{
    return sanitize(text, [](char32_t value) { return xml_1_0_character(value); });
}

} // namespace skan::core::text
