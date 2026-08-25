#include "packet/icmpv6.hpp"

#include <algorithm>
#include <limits>

#include "packet/checksum.hpp"

namespace skan::packet {

ICMPv6::ICMPv6(Icmpv6Type type) noexcept : type_(type) {}

Icmpv6Type ICMPv6::type() const noexcept { return type_; }
std::uint8_t ICMPv6::code() const noexcept { return code_; }
std::uint16_t ICMPv6::checksum() const noexcept { return checksum_; }
std::uint32_t ICMPv6::rest_word() const noexcept { return rest_word_; }
std::uint16_t ICMPv6::identifier() const noexcept { return static_cast<std::uint16_t>(rest_word_ >> 16U); }
std::uint16_t ICMPv6::sequence() const noexcept { return static_cast<std::uint16_t>(rest_word_ & 0xFFFFU); }
const std::vector<std::uint8_t> &ICMPv6::payload() const noexcept { return payload_; }

void ICMPv6::set_type(Icmpv6Type type) noexcept { type_ = type; }
void ICMPv6::set_code(std::uint8_t value) noexcept { code_ = value; }
void ICMPv6::set_rest_word(std::uint32_t value) noexcept { rest_word_ = value; }
void ICMPv6::set_identifier(std::uint16_t value) noexcept
{
    rest_word_ = (static_cast<std::uint32_t>(value) << 16U) | (rest_word_ & 0xFFFFU);
}
void ICMPv6::set_sequence(std::uint16_t value) noexcept
{
    rest_word_ = (rest_word_ & 0xFFFF0000U) | static_cast<std::uint32_t>(value);
}
void ICMPv6::set_payload(std::vector<std::uint8_t> payload) { payload_ = std::move(payload); }

std::size_t ICMPv6::serialized_size() const noexcept
{
    return kHeaderSize + payload_.size();
}

core::StatusCode ICMPv6::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }
    output[0] = static_cast<std::uint8_t>(type_);
    output[1] = code_;
    wire::write_u16(output, 2U, checksum_);
    wire::write_u32(output, 4U, rest_word_);
    std::copy(payload_.begin(), payload_.end(), output.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
    return core::StatusCode::Ok;
}

core::StatusCode ICMPv6::serialize_with_checksum(
    std::span<std::uint8_t> output,
    const std::array<std::uint8_t, 16U> &source_address,
    const std::array<std::uint8_t, 16U> &destination_address) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }
    std::vector<std::uint8_t> bytes(serialized_size(), 0U);
    if (serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return core::StatusCode::InvalidArgument;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 2U, 0U);
    const std::uint16_t calculated = checksum::ipv6_pseudo_header(
        source_address, destination_address, 58U, std::span<const std::uint8_t>{bytes});
    wire::write_u16(std::span<std::uint8_t>{bytes}, 2U, calculated == 0U ? 0xFFFFU : calculated);
    std::copy(bytes.begin(), bytes.end(), output.begin());
    return core::StatusCode::Ok;
}

bool ICMPv6::is_supported_type(std::uint8_t value) noexcept
{
    switch (value) {
    case 1U:
    case 2U:
    case 3U:
    case 4U:
    case 128U:
    case 129U:
    case 135U:
    case 136U:
        return true;
    default:
        return false;
    }
}

bool ICMPv6::validate() const noexcept
{
    if (!is_supported_type(static_cast<std::uint8_t>(type_)) ||
        serialized_size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())) {
        return false;
    }
    const std::uint8_t value = static_cast<std::uint8_t>(type_);
    if ((value == 2U || value == 128U || value == 129U || value == 135U || value == 136U) && code_ != 0U) {
        return false;
    }
    return true;
}

std::optional<ICMPv6> ICMPv6::parse(std::span<const std::uint8_t> input) noexcept
{
    if (input.size() < kHeaderSize || !is_supported_type(input[0])) {
        return std::nullopt;
    }
    ICMPv6 message;
    message.type_ = static_cast<Icmpv6Type>(input[0]);
    message.code_ = input[1];
    message.checksum_ = wire::read_u16(input, 2U);
    message.rest_word_ = wire::read_u32(input, 4U);
    message.payload_.assign(input.begin() + static_cast<std::ptrdiff_t>(kHeaderSize), input.end());
    if (!message.validate()) {
        return std::nullopt;
    }
    return message;
}

} // namespace skan::packet
