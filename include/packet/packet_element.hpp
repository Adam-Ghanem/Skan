#ifndef SKAN_PACKET_PACKET_ELEMENT_HPP
#define SKAN_PACKET_PACKET_ELEMENT_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/status.hpp"

namespace skan::packet {

namespace wire {

inline void write_u16(std::span<std::uint8_t> output, std::size_t offset, std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1U] = static_cast<std::uint8_t>(value & 0xFFU);
}

inline void write_u32(std::span<std::uint8_t> output, std::size_t offset, std::uint32_t value) noexcept
{
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1U] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    output[offset + 2U] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    output[offset + 3U] = static_cast<std::uint8_t>(value & 0xFFU);
}

inline std::uint16_t read_u16(std::span<const std::uint8_t> input, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[offset]) << 8U) |
                                       static_cast<std::uint16_t>(input[offset + 1U]));
}

inline std::uint32_t read_u32(std::span<const std::uint8_t> input, std::size_t offset) noexcept
{
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
}

} // namespace wire

class PacketElement {
public:
    virtual ~PacketElement() = default;

    virtual std::size_t serialized_size() const noexcept = 0;
    virtual core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept = 0;
    virtual bool validate() const noexcept = 0;

    /** Serialize into an owned vector; an empty vector indicates invalid input or failure. */
    std::vector<std::uint8_t> serialize() const;
};

} // namespace skan::packet

#endif // SKAN_PACKET_PACKET_ELEMENT_HPP
