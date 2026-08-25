#include "packet/packet.hpp"

#include <algorithm>
#include <utility>

namespace skan::packet {

void Packet::set_ethernet(Ethernet ethernet)
{
    ethernet_ = std::make_unique<Ethernet>(std::move(ethernet));
}

void Packet::set_ipv4(IPv4 ipv4)
{
    ipv4_ = std::make_unique<IPv4>(std::move(ipv4));
    ipv6_.reset();
}

void Packet::set_ipv6(IPv6 ipv6)
{
    ipv6_ = std::make_unique<IPv6>(std::move(ipv6));
    ipv4_.reset();
}

void Packet::set_tcp(TCP tcp)
{
    tcp_ = std::make_unique<TCP>(std::move(tcp));
    udp_.reset();
    icmp_.reset();
    icmpv6_.reset();
}

void Packet::set_udp(UDP udp)
{
    udp_ = std::make_unique<UDP>(std::move(udp));
    tcp_.reset();
    icmp_.reset();
    icmpv6_.reset();
}

void Packet::set_icmp(ICMP icmp)
{
    icmp_ = std::make_unique<ICMP>(std::move(icmp));
    tcp_.reset();
    udp_.reset();
    icmpv6_.reset();
}

void Packet::set_icmpv6(ICMPv6 icmpv6)
{
    icmpv6_ = std::make_unique<ICMPv6>(std::move(icmpv6));
    tcp_.reset();
    udp_.reset();
    icmp_.reset();
}

const Ethernet *Packet::ethernet() const noexcept { return ethernet_.get(); }
const IPv4 *Packet::ipv4() const noexcept { return ipv4_.get(); }
const IPv6 *Packet::ipv6() const noexcept { return ipv6_.get(); }
const TCP *Packet::tcp() const noexcept { return tcp_.get(); }
const UDP *Packet::udp() const noexcept { return udp_.get(); }
const ICMP *Packet::icmp() const noexcept { return icmp_.get(); }
const ICMPv6 *Packet::icmpv6() const noexcept { return icmpv6_.get(); }

std::size_t Packet::serialized_size() const noexcept
{
    std::size_t size = 0U;
    if (ethernet_ != nullptr) {
        size += ethernet_->serialized_size();
    }
    if (ipv4_ != nullptr) {
        size += ipv4_->serialized_size();
    } else if (ipv6_ != nullptr) {
        size += ipv6_->serialized_size();
    }
    if (tcp_ != nullptr) {
        size += tcp_->serialized_size();
    } else if (udp_ != nullptr) {
        size += udp_->serialized_size();
    } else if (icmp_ != nullptr) {
        size += icmp_->serialized_size();
    } else if (icmpv6_ != nullptr) {
        size += icmpv6_->serialized_size();
    }
    return size;
}

core::StatusCode Packet::serialize(std::span<std::uint8_t> output) const noexcept
{
    if (!validate() || output.size() < serialized_size()) {
        return core::StatusCode::InvalidArgument;
    }

    std::size_t offset = 0U;
    const std::size_t transport_size = tcp_ != nullptr ? tcp_->serialized_size() :
        (udp_ != nullptr ? udp_->serialized_size() :
        (icmp_ != nullptr ? icmp_->serialized_size() : icmpv6_->serialized_size()));

    if (ethernet_ != nullptr) {
        const std::span<std::uint8_t> destination = output.subspan(offset, ethernet_->serialized_size());
        if (ethernet_->serialize(destination) != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
        offset += ethernet_->serialized_size();
    }

    if (ipv4_ != nullptr) {
        IPv4 composed_ipv4 = *ipv4_;
        composed_ipv4.set_total_length(static_cast<std::uint16_t>(ipv4_->serialized_size() + transport_size));
        const std::span<std::uint8_t> destination = output.subspan(offset, composed_ipv4.serialized_size());
        if (composed_ipv4.serialize(destination) != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
        offset += composed_ipv4.serialized_size();
    } else {
        IPv6 composed_ipv6 = *ipv6_;
        composed_ipv6.set_payload_length(static_cast<std::uint16_t>(transport_size));
        const std::span<std::uint8_t> destination = output.subspan(offset, composed_ipv6.serialized_size());
        if (composed_ipv6.serialize(destination) != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
        offset += composed_ipv6.serialized_size();
    }

    if (tcp_ != nullptr) {
        const std::span<std::uint8_t> destination = output.subspan(offset, tcp_->serialized_size());
        const core::StatusCode status = ipv4_ != nullptr
            ? tcp_->serialize_with_checksum(destination, ipv4_->source_address(), ipv4_->destination_address())
            : tcp_->serialize_with_checksum(destination, ipv6_->source_address(), ipv6_->destination_address());
        if (status != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
    } else if (udp_ != nullptr) {
        const std::span<std::uint8_t> destination = output.subspan(offset, udp_->serialized_size());
        const core::StatusCode status = ipv4_ != nullptr
            ? udp_->serialize_with_checksum(destination, ipv4_->source_address(), ipv4_->destination_address())
            : udp_->serialize_with_checksum(destination, ipv6_->source_address(), ipv6_->destination_address());
        if (status != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
    } else if (icmp_ != nullptr) {
        const std::span<std::uint8_t> destination = output.subspan(offset, icmp_->serialized_size());
        if (icmp_->serialize(destination) != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
    } else {
        const std::span<std::uint8_t> destination = output.subspan(offset, icmpv6_->serialized_size());
        if (icmpv6_->serialize_with_checksum(destination, ipv6_->source_address(), ipv6_->destination_address()) != core::StatusCode::Ok) {
            return core::StatusCode::InvalidArgument;
        }
    }
    return core::StatusCode::Ok;
}

std::vector<std::uint8_t> Packet::serialize() const
{
    std::vector<std::uint8_t> output(serialized_size(), 0U);
    if (serialize(std::span<std::uint8_t>{output}) != core::StatusCode::Ok) {
        output.clear();
    }
    return output;
}

bool Packet::validate() const noexcept
{
    const bool has_ipv4 = ipv4_ != nullptr;
    const bool has_ipv6 = ipv6_ != nullptr;
    const bool has_transport = tcp_ != nullptr || udp_ != nullptr || icmp_ != nullptr || icmpv6_ != nullptr;
    if ((has_ipv4 == has_ipv6) || !has_transport) {
        return false;
    }
    if (ethernet_ != nullptr && !ethernet_->validate()) {
        return false;
    }
    if (has_ipv4 && !ipv4_->validate()) {
        return false;
    }
    if (has_ipv6 && !ipv6_->validate()) {
        return false;
    }
    if (tcp_ != nullptr) {
        return tcp_->validate() && ((has_ipv4 && ipv4_->protocol() == 6U) || (has_ipv6 && ipv6_->next_header() == 6U));
    }
    if (udp_ != nullptr) {
        return udp_->validate() && ((has_ipv4 && ipv4_->protocol() == 17U) || (has_ipv6 && ipv6_->next_header() == 17U));
    }
    if (icmp_ != nullptr) {
        return icmp_->validate() && has_ipv4 && ipv4_->protocol() == 1U;
    }
    return icmpv6_->validate() && has_ipv6 && ipv6_->next_header() == 58U;
}

} // namespace skan::packet
