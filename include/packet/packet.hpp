#ifndef SKAN_PACKET_PACKET_HPP
#define SKAN_PACKET_PACKET_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "core/status.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/packet_element.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"

namespace skan::packet {

/**
 * Offline packet composer. Layers are borrowed by value through shared ownership and serialize in
 * Ethernet, IPv4, then TCP/UDP/ICMP order. It never opens descriptors or transmits bytes.
 */
class Packet final {
public:
    Packet() = default;

    void set_ethernet(Ethernet ethernet);
    void set_ipv4(IPv4 ipv4);
    void set_tcp(TCP tcp);
    void set_udp(UDP udp);
    void set_icmp(ICMP icmp);

    const Ethernet *ethernet() const noexcept;
    const IPv4 *ipv4() const noexcept;
    const TCP *tcp() const noexcept;
    const UDP *udp() const noexcept;
    const ICMP *icmp() const noexcept;

    std::size_t serialized_size() const noexcept;
    core::StatusCode serialize(std::span<std::uint8_t> output) const noexcept;
    std::vector<std::uint8_t> serialize() const;
    bool validate() const noexcept;

private:
    std::unique_ptr<Ethernet> ethernet_{};
    std::unique_ptr<IPv4> ipv4_{};
    std::unique_ptr<TCP> tcp_{};
    std::unique_ptr<UDP> udp_{};
    std::unique_ptr<ICMP> icmp_{};
};

} // namespace skan::packet

#endif // SKAN_PACKET_PACKET_HPP
