#ifndef SKAN_PACKET_TCP_HPP
#define SKAN_PACKET_TCP_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "packet/packet_element.hpp"

namespace skan::packet {

enum class TcpFlag : std::uint16_t {
    Fin = 0x0001U,
    Syn = 0x0002U,
    Rst = 0x0004U,
    Psh = 0x0008U,
    Ack = 0x0010U,
    Urg = 0x0020U,
    Ece = 0x0040U,
    Cwr = 0x0080U
};

constexpr std::uint16_t operator|(TcpFlag left, TcpFlag right) noexcept
{
    return static_cast<std::uint16_t>(left) | static_cast<std::uint16_t>(right);
}

constexpr bool has_flag(std::uint16_t flags, TcpFlag flag) noexcept
{
    return (flags & static_cast<std::uint16_t>(flag)) != 0U;
}

enum class TcpOptionKind : std::uint8_t {
    Mss = 2U,
    WindowScale = 3U,
    SackPermitted = 4U,
    Timestamp = 8U
};

struct TcpOption final {
    TcpOptionKind kind{TcpOptionKind::Mss};
    std::uint16_t value{0U};
    std::uint32_t timestamp_value{0U};
    std::uint32_t timestamp_echo{0U};
};

class TCP final : public PacketElement {
public:
    static constexpr std::size_t kMinimumHeaderSize = 20U;

    TCP() = default;

    std::uint16_t source_port() const noexcept;
    std::uint16_t destination_port() const noexcept;
    std::uint32_t sequence_number() const noexcept;
    std::uint32_t acknowledgment_number() const noexcept;
    std::uint8_t data_offset() const noexcept;
    std::uint16_t flags() const noexcept;
    std::uint16_t window() const noexcept;
    std::uint16_t checksum() const noexcept;
    std::uint16_t urgent_pointer() const noexcept;
    const std::vector<TcpOption> &options() const noexcept;
    const std::vector<std::uint8_t> &payload() const noexcept;

    void set_source_port(std::uint16_t value) noexcept;
    void set_destination_port(std::uint16_t value) noexcept;
    void set_sequence_number(std::uint32_t value) noexcept;
    void set_acknowledgment_number(std::uint32_t value) noexcept;
    void set_flags(std::uint16_t value) noexcept;
    void set_window(std::uint16_t value) noexcept;
    void set_urgent_pointer(std::uint16_t value) noexcept;
    void set_options(std::vector<TcpOption> options);
    void set_payload(std::vector<std::uint8_t> payload);

    using PacketElement::serialize;

    std::size_t serialized_size() const noexcept override;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept override;
    bool validate() const noexcept override;

    /** Serialize with the IPv4 pseudo-header checksum populated. */
    core::StatusCode serialize_with_checksum(
        std::span<std::uint8_t> output,
        std::uint32_t source_address,
        std::uint32_t destination_address,
        std::span<const std::uint8_t> payload = {}) const;

    /** Calculate the TCP checksum over the header and payload using IPv4 addresses. */
    std::uint16_t checksum_for_ipv4(
        std::uint32_t source_address,
        std::uint32_t destination_address,
        std::span<const std::uint8_t> payload = {}) const;

    /** Parse a TCP header and its options without reading beyond input. */
    static std::optional<TCP> parse(std::span<const std::uint8_t> input);

private:
    std::size_t header_size() const noexcept;

    std::uint16_t source_port_{0U};
    std::uint16_t destination_port_{0U};
    std::uint32_t sequence_number_{0U};
    std::uint32_t acknowledgment_number_{0U};
    std::uint8_t data_offset_{5U};
    std::uint16_t flags_{0U};
    std::uint16_t window_{0U};
    std::uint16_t checksum_{0U};
    std::uint16_t urgent_pointer_{0U};
    std::vector<TcpOption> options_{};
    std::vector<std::uint8_t> payload_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_TCP_HPP
