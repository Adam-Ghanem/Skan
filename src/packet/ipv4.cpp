#include "packet/ipv4.hpp"

#include <algorithm>

#include "packet/checksum.hpp"

namespace skan::packet {

std::uint8_t IPv4::version() const noexcept { return version_; }
std::uint8_t IPv4::ihl() const noexcept { return ihl_; }
std::uint8_t IPv4::dscp_ecn() const noexcept { return dscp_ecn_; }
std::uint16_t IPv4::total_length() const noexcept { return total_length_; }
std::uint16_t IPv4::identification() const noexcept { return identification_; }
std::uint16_t IPv4::flags_fragment_offset() const noexcept { return flags_fragment_offset_; }
std::uint8_t IPv4::ttl() const noexcept { return ttl_; }
std::uint8_t IPv4::protocol() const noexcept { return protocol_; }
std::uint16_t IPv4::header_checksum() const noexcept { return header_checksum_; }
std::uint32_t IPv4::source_address() const noexcept { return source_address_; }
std::uint32_t IPv4::destination_address() const noexcept { return destination_address_; }

void IPv4::set_version(std::uint8_t value) noexcept { version_ = value; }
void IPv4::set_ihl(std::uint8_t value) noexcept { ihl_ = value; }
void IPv4::set_dscp_ecn(std::uint8_t value) noexcept { dscp_ecn_ = value; }
void IPv4::set_total_length(std::uint16_t value) noexcept { total_length_ = value; }
void IPv4::set_identification(std::uint16_t value) noexcept { identification_ = value; }
void IPv4::set_flags_fragment_offset(std::uint16_t value) noexcept { flags_fragment_offset_ = value; }
void IPv4::set_ttl(std::uint8_t value) noexcept { ttl_ = value; }
void IPv4::set_protocol(std::uint8_t value) noexcept { protocol_ = value; }
void IPv4::set_source_address(std::uint32_t value) noexcept { source_address_ = value; }
void IPv4::set_destination_address(std::uint32_t value) noexcept { destination_address_ = value; }

std::size_t IPv4::serialized_size() const noexcept
{
    return static_cast<std::size_t>(ihl_) * 4U;
}

core::StatusCode IPv4::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    const std::size_t header_size = serialized_size();
    std::fill(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(header_size), 0U);
    output[0] = static_cast<std::uint8_t>((version_ << 4U) | (ihl_ & 0x0FU));
    output[1] = dscp_ecn_;
    wire::write_u16(output, 2U, total_length_);
    wire::write_u16(output, 4U, identification_);
    wire::write_u16(output, 6U, flags_fragment_offset_);
    output[8] = ttl_;
    output[9] = protocol_;
    wire::write_u16(output, 10U, 0U);
    wire::write_u32(output, 12U, source_address_);
    wire::write_u32(output, 16U, destination_address_);

    const std::uint16_t calculated = checksum::internet(std::span<const std::uint8_t>{output.first(header_size)});
    wire::write_u16(output, 10U, calculated);
    return core::StatusCode::Ok;
}

bool IPv4::validate() const noexcept
{
    return version_ == 4U && ihl_ == 5U &&
           total_length_ >= static_cast<std::uint16_t>(serialized_size());
}

std::optional<IPv4> IPv4::parse(std::span<const std::uint8_t> input) noexcept
{
    if (input.size() < kMinimumHeaderSize) {
        return std::nullopt;
    }

    const std::uint8_t version = static_cast<std::uint8_t>(input[0] >> 4U);
    const std::uint8_t ihl = static_cast<std::uint8_t>(input[0] & 0x0FU);
    const std::size_t header_size = static_cast<std::size_t>(ihl) * 4U;
    if (version != 4U || ihl != 5U || input.size() < header_size) {
        return std::nullopt;
    }

    IPv4 ipv4;
    ipv4.version_ = version;
    ipv4.ihl_ = ihl;
    ipv4.dscp_ecn_ = input[1];
    ipv4.total_length_ = wire::read_u16(input, 2U);
    ipv4.identification_ = wire::read_u16(input, 4U);
    ipv4.flags_fragment_offset_ = wire::read_u16(input, 6U);
    ipv4.ttl_ = input[8];
    ipv4.protocol_ = input[9];
    ipv4.header_checksum_ = wire::read_u16(input, 10U);
    ipv4.source_address_ = wire::read_u32(input, 12U);
    ipv4.destination_address_ = wire::read_u32(input, 16U);

    if (!ipv4.validate() || ipv4.total_length_ > input.size() ||
        checksum::internet(input.first(header_size)) != 0U) {
        return std::nullopt;
    }
    return ipv4;
}

} // namespace skan::packet
