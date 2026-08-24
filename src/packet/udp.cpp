#include "packet/udp.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "packet/checksum.hpp"

namespace skan::packet {

std::uint16_t UDP::source_port() const noexcept { return source_port_; }
std::uint16_t UDP::destination_port() const noexcept { return destination_port_; }
std::uint16_t UDP::length() const noexcept { return static_cast<std::uint16_t>(kHeaderSize + payload_.size()); }
std::uint16_t UDP::checksum() const noexcept { return checksum_; }
const std::vector<std::uint8_t> &UDP::payload() const noexcept { return payload_; }

void UDP::set_source_port(std::uint16_t value) noexcept { source_port_ = value; }
void UDP::set_destination_port(std::uint16_t value) noexcept { destination_port_ = value; }
void UDP::set_payload(std::vector<std::uint8_t> payload) { payload_ = std::move(payload); }

std::size_t UDP::serialized_size() const noexcept
{
    return kHeaderSize + payload_.size();
}

core::StatusCode UDP::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    wire::write_u16(output, 0U, source_port_);
    wire::write_u16(output, 2U, destination_port_);
    wire::write_u16(output, 4U, length());
    wire::write_u16(output, 6U, checksum_);
    std::copy(payload_.begin(), payload_.end(), output.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
    return core::StatusCode::Ok;
}

bool UDP::validate() const noexcept
{
    return serialized_size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max());
}

core::StatusCode UDP::serialize_with_checksum(
    std::span<std::uint8_t> output,
    std::uint32_t source_address,
    std::uint32_t destination_address) const
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }
    const std::size_t size = serialized_size();
    std::vector<std::uint8_t> bytes(size, 0U);
    if (serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return core::StatusCode::InvalidArgument;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 6U, 0U);
    const std::uint16_t calculated = checksum::ipv4_pseudo_header(
        source_address, destination_address, 17U, std::span<const std::uint8_t>{bytes});
    wire::write_u16(std::span<std::uint8_t>{bytes}, 6U, calculated == 0U ? 0xFFFFU : calculated);
    std::copy(bytes.begin(), bytes.end(), output.begin());
    return core::StatusCode::Ok;
}

std::uint16_t UDP::checksum_for_ipv4(
    std::uint32_t source_address,
    std::uint32_t destination_address) const
{
    if (!validate()) {
        return 0U;
    }
    std::vector<std::uint8_t> bytes(serialized_size(), 0U);
    if (serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return 0U;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 6U, 0U);
    const std::uint16_t calculated = checksum::ipv4_pseudo_header(
        source_address, destination_address, 17U, std::span<const std::uint8_t>{bytes});
    return calculated == 0U ? 0xFFFFU : calculated;
}

std::optional<UDP> UDP::parse(std::span<const std::uint8_t> input)
{
    if (input.size() < kHeaderSize) {
        return std::nullopt;
    }

    UDP udp;
    udp.source_port_ = wire::read_u16(input, 0U);
    udp.destination_port_ = wire::read_u16(input, 2U);
    const std::uint16_t length = wire::read_u16(input, 4U);
    udp.checksum_ = wire::read_u16(input, 6U);
    if (length < kHeaderSize || static_cast<std::size_t>(length) != input.size()) {
        return std::nullopt;
    }
    udp.payload_.assign(input.begin() + static_cast<std::ptrdiff_t>(kHeaderSize), input.end());
    return udp;
}

} // namespace skan::packet
