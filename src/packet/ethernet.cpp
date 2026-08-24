#include "packet/ethernet.hpp"

#include <algorithm>

namespace skan::packet {

Ethernet::Ethernet(MacAddress destination, MacAddress source, std::uint16_t ether_type) noexcept
    : destination_(destination), source_(source), ether_type_(ether_type)
{
}

const Ethernet::MacAddress &Ethernet::destination() const noexcept
{
    return destination_;
}

const Ethernet::MacAddress &Ethernet::source() const noexcept
{
    return source_;
}

std::uint16_t Ethernet::ether_type() const noexcept
{
    return ether_type_;
}

void Ethernet::set_destination(MacAddress destination) noexcept
{
    destination_ = destination;
}

void Ethernet::set_source(MacAddress source) noexcept
{
    source_ = source;
}

void Ethernet::set_ether_type(std::uint16_t ether_type) noexcept
{
    ether_type_ = ether_type;
}

std::size_t Ethernet::serialized_size() const noexcept
{
    return kHeaderSize;
}

core::StatusCode Ethernet::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate()) {
        return core::StatusCode::InvalidArgument;
    }
    if (output.size() < kHeaderSize) {
        return core::StatusCode::InvalidArgument;
    }

    std::copy(destination_.begin(), destination_.end(), output.begin());
    std::copy(source_.begin(), source_.end(), output.begin() + 6);
    wire::write_u16(output, 12U, ether_type_);
    return core::StatusCode::Ok;
}

bool Ethernet::validate() const noexcept
{
    return ether_type_ != 0U;
}

std::optional<Ethernet> Ethernet::parse(std::span<const std::uint8_t> input) noexcept
{
    if (input.size() < kHeaderSize) {
        return std::nullopt;
    }

    MacAddress destination{};
    MacAddress source{};
    std::copy_n(input.begin(), destination.size(), destination.begin());
    std::copy_n(input.begin() + 6, source.size(), source.begin());
    Ethernet ethernet(destination, source, wire::read_u16(input, 12U));
    if (!ethernet.validate()) {
        return std::nullopt;
    }
    return ethernet;
}

} // namespace skan::packet
