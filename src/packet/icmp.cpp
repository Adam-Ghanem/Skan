#include "packet/icmp.hpp"

#include <algorithm>
#include <utility>

#include "packet/checksum.hpp"

namespace skan::packet {

ICMP::ICMP(IcmpType type) noexcept : type_(type)
{
}

IcmpType ICMP::type() const noexcept { return type_; }
std::uint8_t ICMP::code() const noexcept { return code_; }
std::uint16_t ICMP::identifier() const noexcept { return identifier_; }
std::uint16_t ICMP::sequence() const noexcept { return sequence_; }
std::uint16_t ICMP::checksum() const noexcept { return checksum_; }
const std::vector<std::uint8_t> &ICMP::payload() const noexcept { return payload_; }

void ICMP::set_type(IcmpType type) noexcept { type_ = type; }
void ICMP::set_code(std::uint8_t value) noexcept { code_ = value; }
void ICMP::set_identifier(std::uint16_t value) noexcept { identifier_ = value; }
void ICMP::set_sequence(std::uint16_t value) noexcept { sequence_ = value; }
void ICMP::set_payload(std::vector<std::uint8_t> payload) { payload_ = std::move(payload); }

std::size_t ICMP::serialized_size() const noexcept
{
    return kHeaderSize + payload_.size();
}

core::StatusCode ICMP::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    const std::uint16_t type_and_code = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(type_)) << 8U) |
        static_cast<std::uint16_t>(code_));
    wire::write_u16(output, 0U, type_and_code);
    wire::write_u16(output, 2U, 0U);
    wire::write_u16(output, 4U, identifier_);
    wire::write_u16(output, 6U, sequence_);
    std::copy(payload_.begin(), payload_.end(), output.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
    const std::uint16_t calculated = checksum::internet(std::span<const std::uint8_t>{output.first(serialized_size())});
    wire::write_u16(output, 2U, calculated);
    return core::StatusCode::Ok;
}

bool ICMP::validate() const noexcept
{
    return (type_ == IcmpType::EchoRequest || type_ == IcmpType::EchoReply) &&
           serialized_size() <= 65535U;
}

std::optional<ICMP> ICMP::parse(std::span<const std::uint8_t> input)
{
    if (input.size() < kHeaderSize) {
        return std::nullopt;
    }
    const std::uint8_t raw_type = input[0];
    if (raw_type != static_cast<std::uint8_t>(IcmpType::EchoRequest) &&
        raw_type != static_cast<std::uint8_t>(IcmpType::EchoReply)) {
        return std::nullopt;
    }

    ICMP icmp(static_cast<IcmpType>(raw_type));
    icmp.code_ = input[1];
    icmp.checksum_ = wire::read_u16(input, 2U);
    icmp.identifier_ = wire::read_u16(input, 4U);
    icmp.sequence_ = wire::read_u16(input, 6U);
    icmp.payload_.assign(input.begin() + static_cast<std::ptrdiff_t>(kHeaderSize), input.end());
    if (checksum::internet(input) != 0U) {
        return std::nullopt;
    }
    return icmp;
}

} // namespace skan::packet
