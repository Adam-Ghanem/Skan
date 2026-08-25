#include "packet/tcp.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

#include "packet/checksum.hpp"

namespace skan::packet {
namespace {

std::size_t option_size(TcpOptionKind kind) noexcept
{
    switch (kind) {
    case TcpOptionKind::Nop:
        return 1U;
    case TcpOptionKind::Mss:
        return 4U;
    case TcpOptionKind::WindowScale:
        return 3U;
    case TcpOptionKind::SackPermitted:
        return 2U;
    case TcpOptionKind::Timestamp:
        return 10U;
    default:
        return 0U;
    }
}

std::size_t padded_options_size(const std::vector<TcpOption> &options) noexcept
{
    std::size_t size = 0U;
    for (const TcpOption &option : options) {
        size += option_size(option.kind);
    }
    return (size + 3U) / 4U * 4U;
}

bool append_options(const std::vector<TcpOption> &options, std::span<std::uint8_t> output) noexcept
{
    std::size_t offset = 0U;
    for (const TcpOption &option : options) {
        const std::size_t size = option_size(option.kind);
        if (size == 0U || offset + size > output.size()) {
            return false;
        }
        output[offset] = static_cast<std::uint8_t>(option.kind);
        if (option.kind == TcpOptionKind::Nop) {
            ++offset;
            continue;
        }
        output[offset + 1U] = static_cast<std::uint8_t>(size);
        switch (option.kind) {
        case TcpOptionKind::Mss:
            wire::write_u16(output, offset + 2U, option.value);
            break;
        case TcpOptionKind::WindowScale:
            if (option.value > 255U) {
                return false;
            }
            output[offset + 2U] = static_cast<std::uint8_t>(option.value);
            break;
        case TcpOptionKind::SackPermitted:
            break;
        case TcpOptionKind::Timestamp:
            wire::write_u32(output, offset + 2U, option.timestamp_value);
            wire::write_u32(output, offset + 6U, option.timestamp_echo);
            break;
        default:
            return false;
        }
        offset += size;
    }
    return true;
}

} // namespace

std::uint16_t TCP::source_port() const noexcept { return source_port_; }
std::uint16_t TCP::destination_port() const noexcept { return destination_port_; }
std::uint32_t TCP::sequence_number() const noexcept { return sequence_number_; }
std::uint32_t TCP::acknowledgment_number() const noexcept { return acknowledgment_number_; }
std::uint8_t TCP::data_offset() const noexcept { return data_offset_; }
std::uint16_t TCP::flags() const noexcept { return flags_; }
std::uint16_t TCP::window() const noexcept { return window_; }
std::uint16_t TCP::checksum() const noexcept { return checksum_; }
std::uint16_t TCP::urgent_pointer() const noexcept { return urgent_pointer_; }
const std::vector<TcpOption> &TCP::options() const noexcept { return options_; }
const std::vector<std::uint8_t> &TCP::payload() const noexcept { return payload_; }

void TCP::set_source_port(std::uint16_t value) noexcept { source_port_ = value; }
void TCP::set_destination_port(std::uint16_t value) noexcept { destination_port_ = value; }
void TCP::set_sequence_number(std::uint32_t value) noexcept { sequence_number_ = value; }
void TCP::set_acknowledgment_number(std::uint32_t value) noexcept { acknowledgment_number_ = value; }
void TCP::set_flags(std::uint16_t value) noexcept { flags_ = value; }
void TCP::set_window(std::uint16_t value) noexcept { window_ = value; }
void TCP::set_urgent_pointer(std::uint16_t value) noexcept { urgent_pointer_ = value; }
void TCP::set_options(std::vector<TcpOption> options)
{
    options_ = std::move(options);
    data_offset_ = static_cast<std::uint8_t>(5U + padded_options_size(options_) / 4U);
}

void TCP::set_payload(std::vector<std::uint8_t> payload)
{
    payload_ = std::move(payload);
}

std::size_t TCP::header_size() const noexcept
{
    return kMinimumHeaderSize + padded_options_size(options_);
}

std::size_t TCP::serialized_size() const noexcept
{
    return header_size() + payload_.size();
}

core::StatusCode TCP::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    const std::size_t header_bytes = header_size();
    std::fill(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(header_bytes), 0U);
    wire::write_u16(output, 0U, source_port_);
    wire::write_u16(output, 2U, destination_port_);
    wire::write_u32(output, 4U, sequence_number_);
    wire::write_u32(output, 8U, acknowledgment_number_);
    output[12] = static_cast<std::uint8_t>(data_offset_ << 4U);
    output[13] = static_cast<std::uint8_t>(flags_ & 0x00FFU);
    wire::write_u16(output, 14U, window_);
    wire::write_u16(output, 16U, checksum_);
    wire::write_u16(output, 18U, urgent_pointer_);

    const std::size_t options_size = header_bytes - kMinimumHeaderSize;
    if (!append_options(options_, output.subspan(kMinimumHeaderSize, options_size))) {
        return core::StatusCode::InvalidArgument;
    }
    std::copy(payload_.begin(), payload_.end(), output.begin() + static_cast<std::ptrdiff_t>(header_bytes));
    return core::StatusCode::Ok;
}

bool TCP::validate() const noexcept
{
    const std::size_t options_size = padded_options_size(options_);
    if (options_size > 40U || payload_.size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) - header_size() ||
        data_offset_ < 5U || data_offset_ > 15U ||
        header_size() != static_cast<std::size_t>(data_offset_) * 4U) {
        return false;
    }
    for (const TcpOption &option : options_) {
        if (option_size(option.kind) == 0U ||
            (option.kind == TcpOptionKind::WindowScale && option.value > 255U)) {
            return false;
        }
    }
    return true;
}

core::StatusCode TCP::serialize_with_checksum(
    std::span<std::uint8_t> output,
    std::uint32_t source_address,
    std::uint32_t destination_address,
    std::span<const std::uint8_t> payload) const
{
    TCP segment = *this;
    if (!payload.empty()) {
        segment.payload_.assign(payload.begin(), payload.end());
    }
    if (!segment.validate() || output.size() < segment.serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    std::vector<std::uint8_t> bytes(segment.serialized_size(), 0U);
    if (segment.serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return core::StatusCode::InvalidArgument;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, 0U);
    const std::uint16_t calculated = checksum::ipv4_pseudo_header(
        source_address, destination_address, 6U, std::span<const std::uint8_t>{bytes});
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, calculated == 0U ? 0xFFFFU : calculated);
    std::copy(bytes.begin(), bytes.end(), output.begin());
    return core::StatusCode::Ok;
}


core::StatusCode TCP::serialize_with_checksum(
    std::span<std::uint8_t> output,
    const std::array<std::uint8_t, 16U> &source_address,
    const std::array<std::uint8_t, 16U> &destination_address,
    std::span<const std::uint8_t> payload) const
{
    TCP segment = *this;
    if (!payload.empty()) {
        segment.payload_.assign(payload.begin(), payload.end());
    }
    if (!segment.validate() || output.size() < segment.serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }
    std::vector<std::uint8_t> bytes(segment.serialized_size(), 0U);
    if (segment.serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return core::StatusCode::InvalidArgument;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, 0U);
    const std::uint16_t calculated = checksum::ipv6_pseudo_header(
        source_address, destination_address, 6U, std::span<const std::uint8_t>{bytes});
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, calculated == 0U ? 0xFFFFU : calculated);
    std::copy(bytes.begin(), bytes.end(), output.begin());
    return core::StatusCode::Ok;
}

std::uint16_t TCP::checksum_for_ipv6(
    const std::array<std::uint8_t, 16U> &source_address,
    const std::array<std::uint8_t, 16U> &destination_address,
    std::span<const std::uint8_t> payload) const
{
    TCP segment = *this;
    if (!payload.empty()) {
        segment.payload_.assign(payload.begin(), payload.end());
    }
    if (!segment.validate()) {
        return 0U;
    }
    std::vector<std::uint8_t> bytes(segment.serialized_size(), 0U);
    if (segment.serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return 0U;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, 0U);
    const std::uint16_t calculated = checksum::ipv6_pseudo_header(
        source_address, destination_address, 6U, std::span<const std::uint8_t>{bytes});
    return calculated == 0U ? 0xFFFFU : calculated;
}

std::uint16_t TCP::checksum_for_ipv4(
    std::uint32_t source_address,
    std::uint32_t destination_address,
    std::span<const std::uint8_t> payload) const
{
    TCP segment = *this;
    if (!payload.empty()) {
        segment.payload_.assign(payload.begin(), payload.end());
    }
    if (!segment.validate()) {
        return 0U;
    }
    std::vector<std::uint8_t> bytes(segment.serialized_size(), 0U);
    if (segment.serialize(std::span<std::uint8_t>{bytes}) != core::StatusCode::Ok) {
        return 0U;
    }
    wire::write_u16(std::span<std::uint8_t>{bytes}, 16U, 0U);
    const std::uint16_t calculated = checksum::ipv4_pseudo_header(
        source_address, destination_address, 6U, std::span<const std::uint8_t>{bytes});
    return calculated == 0U ? 0xFFFFU : calculated;
}

std::optional<TCP> TCP::parse(std::span<const std::uint8_t> input)
{
    if (input.size() < kMinimumHeaderSize) {
        return std::nullopt;
    }
    const std::uint8_t data_offset = static_cast<std::uint8_t>(input[12] >> 4U);
    const std::size_t header_size = static_cast<std::size_t>(data_offset) * 4U;
    if (data_offset < 5U || data_offset > 15U || input.size() < header_size) {
        return std::nullopt;
    }

    TCP tcp;
    tcp.source_port_ = wire::read_u16(input, 0U);
    tcp.destination_port_ = wire::read_u16(input, 2U);
    tcp.sequence_number_ = wire::read_u32(input, 4U);
    tcp.acknowledgment_number_ = wire::read_u32(input, 8U);
    tcp.data_offset_ = data_offset;
    tcp.flags_ = static_cast<std::uint16_t>(input[13]);
    tcp.window_ = wire::read_u16(input, 14U);
    tcp.checksum_ = wire::read_u16(input, 16U);
    tcp.urgent_pointer_ = wire::read_u16(input, 18U);

    std::size_t offset = kMinimumHeaderSize;
    while (offset < header_size) {
        const std::uint8_t kind = input[offset];
        if (kind == 0U) {
            break;
        }
        if (kind == 1U) {
            TcpOption option;
            option.kind = TcpOptionKind::Nop;
            tcp.options_.push_back(option);
            ++offset;
            continue;
        }
        if (offset + 1U >= header_size) {
            return std::nullopt;
        }
        const std::uint8_t length = input[offset + 1U];
        if (length < 2U || offset + length > header_size) {
            return std::nullopt;
        }
        TcpOption option;
        switch (kind) {
        case static_cast<std::uint8_t>(TcpOptionKind::Mss):
            if (length != 4U) {
                return std::nullopt;
            }
            option.kind = TcpOptionKind::Mss;
            option.value = wire::read_u16(input, offset + 2U);
            break;
        case static_cast<std::uint8_t>(TcpOptionKind::WindowScale):
            if (length != 3U) {
                return std::nullopt;
            }
            option.kind = TcpOptionKind::WindowScale;
            option.value = input[offset + 2U];
            break;
        case static_cast<std::uint8_t>(TcpOptionKind::SackPermitted):
            if (length != 2U) {
                return std::nullopt;
            }
            option.kind = TcpOptionKind::SackPermitted;
            break;
        case static_cast<std::uint8_t>(TcpOptionKind::Timestamp):
            if (length != 10U) {
                return std::nullopt;
            }
            option.kind = TcpOptionKind::Timestamp;
            option.timestamp_value = wire::read_u32(input, offset + 2U);
            option.timestamp_echo = wire::read_u32(input, offset + 6U);
            break;
        default:
            // Unknown options are valid TCP wire data; preserve parser alignment while
            // exposing only option kinds represented by the public value model.
            offset += length;
            continue;
        }
        tcp.options_.push_back(option);
        offset += length;
    }
    if (input.size() - header_size >
        static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) - header_size) {
        return std::nullopt;
    }
    tcp.payload_.assign(input.begin() + static_cast<std::ptrdiff_t>(header_size), input.end());
    // The public model intentionally exposes only recognized options, so its
    // derived option size may be smaller than the wire data offset. The wire
    // header and payload bounds above are the authoritative parse checks.
    return tcp;
}

} // namespace skan::packet
