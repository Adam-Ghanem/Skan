#ifndef SKAN_NET_PACKET_FILTER_HPP
#define SKAN_NET_PACKET_FILTER_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "core/types.hpp"
#include "net/packet_receiver.hpp"

namespace skan::net {

enum class PacketProtocol {
    Any,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ICMPv6
};

struct PacketFilter final {
    std::optional<PacketProtocol> protocol;
    std::optional<std::uint16_t> source_port;
    std::optional<std::uint16_t> destination_port;
};

bool matches(const PacketFilter &filter, const PacketObservation &packet) noexcept;

struct CorrelationKey final {
    std::uint32_t target_ipv4{0U};
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    std::uint32_t sequence{0U};
    core::IpAddress target_ip{};

    bool operator==(const CorrelationKey &) const noexcept = default;
};

struct CorrelationKeyHash final {
    std::size_t operator()(const CorrelationKey &key) const noexcept;
};

enum class CorrelationStatus {
    Inserted,
    Duplicate,
    Found,
    Removed,
    NotFound,
    Late
};

struct CorrelationEntry final {
    CorrelationKey key;
    std::uint64_t token{0U};
    std::chrono::steady_clock::time_point expires_at{};
};

struct CorrelationResult final {
    CorrelationStatus status{CorrelationStatus::NotFound};
    std::optional<CorrelationEntry> entry;
};

class CorrelationTable final {
public:
    CorrelationStatus insert(
        CorrelationKey key,
        std::uint64_t token,
        std::chrono::steady_clock::time_point expires_at);
    CorrelationResult lookup(
        const CorrelationKey &key,
        std::chrono::steady_clock::time_point now);
    CorrelationStatus remove(const CorrelationKey &key) noexcept;
    void clear() noexcept;
    std::size_t remove_expired(std::chrono::steady_clock::time_point now);
    bool contains(const CorrelationKey &key) const noexcept;
    std::size_t size() const noexcept;

private:
    std::unordered_map<CorrelationKey, CorrelationEntry, CorrelationKeyHash> entries_;
};

} // namespace skan::net

#endif // SKAN_NET_PACKET_FILTER_HPP
