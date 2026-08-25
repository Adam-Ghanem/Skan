#include "packet/ipv6.hpp"


namespace skan::packet {

std::uint8_t IPv6::version() const noexcept { return version_; }
std::uint8_t IPv6::traffic_class() const noexcept { return traffic_class_; }
std::uint32_t IPv6::flow_label() const noexcept { return flow_label_; }
std::uint16_t IPv6::payload_length() const noexcept { return payload_length_; }
std::uint8_t IPv6::next_header() const noexcept { return next_header_; }
std::uint8_t IPv6::hop_limit() const noexcept { return hop_limit_; }
const std::array<std::uint8_t, 16U> &IPv6::source_address() const noexcept { return source_address_; }
const std::array<std::uint8_t, 16U> &IPv6::destination_address() const noexcept { return destination_address_; }

void IPv6::set_version(std::uint8_t value) noexcept { version_ = value; }
void IPv6::set_traffic_class(std::uint8_t value) noexcept { traffic_class_ = value; }
void IPv6::set_flow_label(std::uint32_t value) noexcept { flow_label_ = value & 0x000FFFFFU; }
void IPv6::set_payload_length(std::uint16_t value) noexcept { payload_length_ = value; }
void IPv6::set_next_header(std::uint8_t value) noexcept { next_header_ = value; }
void IPv6::set_hop_limit(std::uint8_t value) noexcept { hop_limit_ = value; }
void IPv6::set_source_address(const std::array<std::uint8_t, 16U> &value) noexcept { source_address_ = value; }
void IPv6::set_destination_address(const std::array<std::uint8_t, 16U> &value) noexcept { destination_address_ = value; }

std::size_t IPv6::serialized_size() const noexcept { return kHeaderSize; }

core::StatusCode IPv6::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < kHeaderSize) {
        return core::StatusCode::InvalidArgument;
    }
    output[0] = static_cast<std::uint8_t>((version_ << 4U) | (traffic_class_ >> 4U));
    output[1] = static_cast<std::uint8_t>((traffic_class_ << 4U) | ((flow_label_ >> 16U) & 0x0FU));
    output[2] = static_cast<std::uint8_t>(flow_label_ >> 8U);
    output[3] = static_cast<std::uint8_t>(flow_label_ & 0xFFU);
    wire::write_u16(output, 4U, payload_length_);
    output[6] = next_header_;
    output[7] = hop_limit_;
    for (std::size_t index = 0U; index < 16U; ++index) {
        output[8U + index] = source_address_[index];
        output[24U + index] = destination_address_[index];
    }
    return core::StatusCode::Ok;
}

bool IPv6::validate() const noexcept
{
    return version_ == 6U && (flow_label_ & 0xFFF00000U) == 0U;
}

std::optional<IPv6> IPv6::parse(std::span<const std::uint8_t> input) noexcept
{
    if (input.size() < kHeaderSize || (input[0] >> 4U) != 6U) {
        return std::nullopt;
    }
    IPv6 result;
    result.version_ = static_cast<std::uint8_t>(input[0] >> 4U);
    result.traffic_class_ = static_cast<std::uint8_t>(((input[0] & 0x0FU) << 4U) | (input[1] >> 4U));
    result.flow_label_ = (static_cast<std::uint32_t>(input[1] & 0x0FU) << 16U) |
                         (static_cast<std::uint32_t>(input[2]) << 8U) |
                         static_cast<std::uint32_t>(input[3]);
    result.payload_length_ = wire::read_u16(input, 4U);
    if (static_cast<std::size_t>(result.payload_length_) > input.size() - kHeaderSize) {
        return std::nullopt;
    }
    result.next_header_ = input[6];
    result.hop_limit_ = input[7];
    for (std::size_t index = 0U; index < 16U; ++index) {
        result.source_address_[index] = input[8U + index];
        result.destination_address_[index] = input[24U + index];
    }
    return result;
}

} // namespace skan::packet
