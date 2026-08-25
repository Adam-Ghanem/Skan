#include "net/packet_filter.hpp"

namespace skan::net {

bool matches(const PacketFilter &filter, const PacketObservation &packet) noexcept
{
    if (!packet.valid()) {
        return false;
    }
    const PacketProtocol protocol = filter.protocol.value_or(PacketProtocol::Any);
    switch (protocol) {
    case PacketProtocol::Any:
        break;
    case PacketProtocol::IPv4:
        if (!packet.ipv4.has_value()) {
            return false;
        }
        break;
    case PacketProtocol::TCP:
        if (!packet.tcp.has_value()) {
            return false;
        }
        break;
    case PacketProtocol::UDP:
        if (!packet.udp.has_value()) {
            return false;
        }
        break;
    case PacketProtocol::ICMP:
        if (!packet.icmp.has_value()) {
            return false;
        }
        break;
    }

    if (!filter.source_port.has_value() && !filter.destination_port.has_value()) {
        return true;
    }
    if (packet.tcp.has_value()) {
        if (filter.source_port.has_value() && packet.tcp->source_port() != *filter.source_port) {
            return false;
        }
        if (filter.destination_port.has_value() && packet.tcp->destination_port() != *filter.destination_port) {
            return false;
        }
        return true;
    }
    if (packet.udp.has_value()) {
        if (filter.source_port.has_value() && packet.udp->source_port() != *filter.source_port) {
            return false;
        }
        if (filter.destination_port.has_value() && packet.udp->destination_port() != *filter.destination_port) {
            return false;
        }
        return true;
    }
    return false;
}

std::size_t CorrelationKeyHash::operator()(const CorrelationKey &key) const noexcept
{
    std::size_t hash = static_cast<std::size_t>(key.target_ipv4);
    hash ^= static_cast<std::size_t>(key.source_port) + static_cast<std::size_t>(0x9e3779b9U) +
            (hash << 6U) + (hash >> 2U);
    hash ^= static_cast<std::size_t>(key.destination_port) + static_cast<std::size_t>(0x9e3779b9U) +
            (hash << 6U) + (hash >> 2U);
    hash ^= static_cast<std::size_t>(key.sequence) + static_cast<std::size_t>(0x9e3779b9U) +
            (hash << 6U) + (hash >> 2U);
    return hash;
}

CorrelationStatus CorrelationTable::insert(
    CorrelationKey key,
    std::uint64_t token,
    std::chrono::steady_clock::time_point expires_at)
{
    const auto found = entries_.find(key);
    if (found != entries_.end()) {
        return CorrelationStatus::Duplicate;
    }
    entries_.emplace(key, CorrelationEntry{key, token, expires_at});
    return CorrelationStatus::Inserted;
}

CorrelationResult CorrelationTable::lookup(
    const CorrelationKey &key,
    std::chrono::steady_clock::time_point now)
{
    const auto found = entries_.find(key);
    if (found == entries_.end()) {
        return CorrelationResult{CorrelationStatus::NotFound, std::nullopt};
    }
    if (now >= found->second.expires_at) {
        entries_.erase(found);
        return CorrelationResult{CorrelationStatus::Late, std::nullopt};
    }
    return CorrelationResult{CorrelationStatus::Found, found->second};
}

CorrelationStatus CorrelationTable::remove(const CorrelationKey &key) noexcept
{
    const auto found = entries_.find(key);
    if (found == entries_.end()) {
        return CorrelationStatus::NotFound;
    }
    entries_.erase(found);
    return CorrelationStatus::Removed;
}

void CorrelationTable::clear() noexcept
{
    entries_.clear();
}

std::size_t CorrelationTable::remove_expired(std::chrono::steady_clock::time_point now)
{
    std::size_t removed = 0U;
    for (auto iterator = entries_.begin(); iterator != entries_.end();) {
        if (now >= iterator->second.expires_at) {
            iterator = entries_.erase(iterator);
            ++removed;
        } else {
            ++iterator;
        }
    }
    return removed;
}

bool CorrelationTable::contains(const CorrelationKey &key) const noexcept
{
    return entries_.find(key) != entries_.end();
}

std::size_t CorrelationTable::size() const noexcept
{
    return entries_.size();
}

} // namespace skan::net
