#ifndef SKAN_PACKET_CHECKSUM_HPP
#define SKAN_PACKET_CHECKSUM_HPP

#include <cstdint>
#include <span>

namespace skan::packet::checksum {

/** Compute the Internet one's-complement checksum over a byte span. */
std::uint16_t internet(std::span<const std::uint8_t> bytes) noexcept;

/** Compute a TCP or UDP checksum using an IPv4 pseudo-header and transport bytes. */
std::uint16_t ipv4_pseudo_header(
    std::uint32_t source_address,
    std::uint32_t destination_address,
    std::uint8_t protocol,
    std::span<const std::uint8_t> transport_bytes) noexcept;

} // namespace skan::packet::checksum

#endif // SKAN_PACKET_CHECKSUM_HPP
