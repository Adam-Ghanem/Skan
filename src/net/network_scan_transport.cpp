#include "net/network_scan_transport.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <new>
#include <utility>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "net/unique_fd.hpp"

#include "packet/ethernet.hpp"
#include "packet/checksum.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/packet.hpp"
#include "packet/tcp.hpp"
#include "core/log.hpp"

namespace skan::net {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint8_t kTcpProtocol = 6U;
constexpr std::size_t kMaximumCaptureBatch = 256U;

// Diagnostics are opt-in and must never change packet admission, including on OOM.
template <typename... Args>
void trace(std::string_view format, const Args &...args) noexcept
{
    if (log::minimum_level() != log::Level::Debug) { return; }
    try { log::debug(format, args...); } catch (...) { }
}

const char *reply_mismatch(const portscan::PortSubmission &submission,
                           const PacketObservation &observation) noexcept
{
    if (!observation.valid()) { return "parser"; }
    if (!observation.tcp) { return "protocol"; }
    core::IpAddress source;
    core::IpAddress destination;
    if (observation.ipv4 && !observation.ipv6) {
        source = core::IpAddress::from_ipv4(observation.ipv4->source_address());
        destination = core::IpAddress::from_ipv4(observation.ipv4->destination_address());
    } else if (observation.ipv6 && !observation.ipv4) {
        source = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        destination = core::IpAddress::from_ipv6(observation.ipv6->destination_address());
    } else { return "AF"; }
    if (source.family != submission.target_ip.family || destination.family != submission.source_ip.family) { return "AF"; }
    if (source.bytes != submission.target_ip.bytes) { return "src-IP"; }
    if (destination.bytes != submission.source_ip.bytes) { return "dst-IP"; }
    const auto &tcp = *observation.tcp;
    if (tcp.source_port() != submission.port.number) { return "src-port"; }
    if (tcp.destination_port() != submission.source_port) { return "dst-port"; }
    if (submission.probe == portscan::ScanProbeType::TcpAck &&
        tcp.sequence_number() != submission.acknowledgment_number) { return "TCP-seq"; }
    if (submission.probe == portscan::ScanProbeType::TcpSyn &&
        packet::has_flag(tcp.flags(), packet::TcpFlag::Ack) &&
        tcp.acknowledgment_number() != submission.sequence_number + 1U) { return "TCP-ack"; }
    return "TCP-flags/probe";
}

std::uint32_t route_word_to_host(unsigned long value) noexcept
{
    const std::uint32_t wire = static_cast<std::uint32_t>(value);
    return ((wire & 0x000000FFU) << 24U) |
           ((wire & 0x0000FF00U) << 8U) |
           ((wire & 0x00FF0000U) >> 8U) |
           ((wire & 0xFF000000U) >> 24U);
}

NetworkScanStatus map_transport_status(TransportStatus status) noexcept
{
    switch (status) {
    case TransportStatus::Success:
        return NetworkScanStatus::Success;
    case TransportStatus::InvalidConfiguration:
        return NetworkScanStatus::InvalidConfiguration;
    case TransportStatus::InterfaceNotFound:
        return NetworkScanStatus::InterfaceNotFound;
    case TransportStatus::PermissionDenied:
        return NetworkScanStatus::PermissionDenied;
    case TransportStatus::NotSupported:
        return NetworkScanStatus::NotSupported;
    case TransportStatus::NotOpen:
    case TransportStatus::Closed:
        return NetworkScanStatus::NotOpen;
    case TransportStatus::SendFailed:
    case TransportStatus::CaptureFailed:
    case TransportStatus::SystemError:
        return NetworkScanStatus::SystemError;
    }
    return NetworkScanStatus::SystemError;
}

NetworkScanResult preflight_failure(const TransportPreflightResult &preflight)
{
    const NetworkScanStatus status = preflight.category == PreflightCategory::InvalidInterface
                                         ? NetworkScanStatus::InterfaceNotFound
                                         : preflight.category == PreflightCategory::NoRoute
                                               ? NetworkScanStatus::RoutingUnavailable
                                               : preflight.category == PreflightCategory::UnsupportedFamily ||
                                                         preflight.category == PreflightCategory::MtuUnavailable
                                                     ? NetworkScanStatus::NotSupported
                                                     : NetworkScanStatus::PermissionDenied;
    NetworkScanResult result{status, preflight.system_error, preflight.message};
    result.category = preflight.category;
    result.family = preflight.family;
    return result;
}

core::StatusCode map_network_status(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return core::StatusCode::Ok;
    case NetworkScanStatus::InvalidConfiguration:
        return core::StatusCode::InvalidArgument;
    case NetworkScanStatus::InterfaceNotFound:
        return core::StatusCode::NotFound;
    case NetworkScanStatus::RoutingUnavailable:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::PermissionDenied:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::NotSupported:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::NotOpen:
    case NetworkScanStatus::SystemError:
        return core::StatusCode::IoError;
    }
    return core::StatusCode::IoError;
}

std::optional<std::array<std::uint8_t, 6U>> parse_mac(std::string_view text)
{
    std::array<std::uint8_t, 6U> mac{};
    std::size_t begin = 0U;
    for (std::size_t index = 0U; index < mac.size(); ++index) {
        const std::size_t end = text.find(':', begin);
        const std::size_t length = end == std::string_view::npos ? text.size() - begin : end - begin;
        if (length == 0U || length > 2U) {
            return std::nullopt;
        }
        unsigned int value = 0U;
        const auto parsed = std::from_chars(text.data() + static_cast<std::ptrdiff_t>(begin),
                                            text.data() + static_cast<std::ptrdiff_t>(begin + length),
                                            value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + static_cast<std::ptrdiff_t>(begin + length) ||
            value > 255U) {
            return std::nullopt;
        }
        mac[index] = static_cast<std::uint8_t>(value);
        if (index + 1U < mac.size()) {
            if (end == std::string_view::npos) {
                return std::nullopt;
            }
            begin = end + 1U;
        } else if (end != std::string_view::npos) {
            return std::nullopt;
        }
    }
    return mac;
}

std::optional<std::array<std::uint8_t, 6U>> local_mac_for(std::string_view interface_name)
{
    const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return std::nullopt;
    }
    ifreq request{};
    if (interface_name.size() >= IFNAMSIZ) {
        (void)::close(descriptor);
        return std::nullopt;
    }
    std::memcpy(request.ifr_name, interface_name.data(), interface_name.size());
    request.ifr_name[interface_name.size()] = '\0';
    if (::ioctl(descriptor, SIOCGIFHWADDR, &request) != 0) {
        (void)::close(descriptor);
        return std::nullopt;
    }
    std::array<std::uint8_t, 6U> mac{};
    std::memcpy(mac.data(), request.ifr_hwaddr.sa_data, mac.size());
    (void)::close(descriptor);
    return mac;
}

std::optional<std::array<std::uint8_t, 6U>> neighbor_mac_for(
    std::string_view interface_name,
    std::uint32_t target_ipv4)
{
    std::ifstream neighbors("/proc/net/arp");
    if (!neighbors.is_open()) {
        return std::nullopt;
    }
    std::string line;
    (void)std::getline(neighbors, line);
    while (std::getline(neighbors, line)) {
        std::istringstream fields(line);
        std::string address;
        std::string hardware_type;
        std::string flags;
        std::string hardware_address;
        std::string mask;
        std::string device;
        if (!(fields >> address >> hardware_type >> flags >> hardware_address >> mask >> device) ||
            device != interface_name) {
            continue;
        }
        in_addr parsed_address{};
        if (::inet_pton(AF_INET, address.c_str(), &parsed_address) != 1 ||
            parsed_address.s_addr != htonl(target_ipv4)) {
            continue;
        }
        return parse_mac(hardware_address);
    }
    return std::nullopt;
}

std::optional<std::array<std::uint8_t, 6U>> ipv6_neighbor_mac_for(
    std::string_view interface_name,
    const std::array<std::uint8_t, 16U> &target_ipv6)
{
    const unsigned int interface_index = ::if_nametoindex(std::string(interface_name).c_str());
    if (interface_index == 0U) {
        return std::nullopt;
    }
    const detail::UniqueFd descriptor{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
    if (descriptor.get() < 0) {
        return std::nullopt;
    }

    // A cache miss must not turn into an unbounded scanner startup wait.
    const timeval receive_timeout{0, 100000};
    if (::setsockopt(descriptor.get(), SOL_SOCKET, SO_RCVTIMEO,
                     &receive_timeout, sizeof(receive_timeout)) != 0) {
        return std::nullopt;
    }

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (::bind(descriptor.get(), reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0) {
        return std::nullopt;
    }

    struct NeighborRequest {
        nlmsghdr header;
        ndmsg neighbor;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
    request.header.nlmsg_type = RTM_GETNEIGH;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 1U;
    request.neighbor.ndm_family = AF_INET6;

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    const ssize_t sent = ::sendto(
        descriptor.get(),
        &request,
        request.header.nlmsg_len,
        MSG_DONTWAIT,
        reinterpret_cast<const sockaddr *>(&kernel),
        sizeof(kernel));
    if (sent != static_cast<ssize_t>(request.header.nlmsg_len)) {
        return std::nullopt;
    }

    std::optional<std::array<std::uint8_t, 6U>> result;
    alignas(nlmsghdr) std::array<std::uint8_t, 8192U> buffer{};
    bool finished = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{100};
    for (std::size_t batch = 0U; batch < 32U && !finished &&
         std::chrono::steady_clock::now() < deadline; ++batch) {
        const ssize_t received = ::recv(descriptor.get(), buffer.data(), buffer.size(), 0);
        if (received <= 0) {
            break;
        }
        int remaining = static_cast<int>(received);
        for (nlmsghdr *header = reinterpret_cast<nlmsghdr *>(buffer.data());
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != request.header.nlmsg_seq) {
                continue;
            }
            if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) {
                finished = true;
                break;
            }
            if (header->nlmsg_type != RTM_NEWNEIGH || header->nlmsg_len < NLMSG_LENGTH(sizeof(ndmsg))) {
                continue;
            }
            const auto *neighbor = static_cast<const ndmsg *>(NLMSG_DATA(header));
            if (neighbor->ndm_family != AF_INET6 ||
                neighbor->ndm_ifindex != static_cast<int>(interface_index) ||
                (neighbor->ndm_state & (NUD_INCOMPLETE | NUD_FAILED)) != 0U) {
                continue;
            }

            std::optional<std::array<std::uint8_t, 16U>> destination;
            std::optional<std::array<std::uint8_t, 6U>> mac;
            int attribute_length = static_cast<int>(header->nlmsg_len) -
                                   static_cast<int>(NLMSG_LENGTH(sizeof(ndmsg)));
            for (const rtattr *attribute = RTM_RTA(neighbor);
                 RTA_OK(attribute, attribute_length);
                 attribute = RTA_NEXT(attribute, attribute_length)) {
                const std::size_t payload_size = static_cast<std::size_t>(RTA_PAYLOAD(attribute));
                if (attribute->rta_type == NDA_DST && payload_size == target_ipv6.size()) {
                    std::array<std::uint8_t, 16U> value{};
                    std::memcpy(value.data(), RTA_DATA(attribute), value.size());
                    destination = value;
                } else if (attribute->rta_type == NDA_LLADDR && payload_size >= 6U) {
                    std::array<std::uint8_t, 6U> value{};
                    std::memcpy(value.data(), RTA_DATA(attribute), value.size());
                    mac = value;
                }
            }
            if (destination.has_value() && *destination == target_ipv6 && mac.has_value()) {
                result = mac;
                finished = true;
                break;
            }
        }
    }
    return result;
}

std::optional<std::uint32_t> ipv4_next_hop_for(std::string_view interface_name, std::uint32_t target_ipv4)
{
    std::ifstream routes("/proc/net/route");
    if (!routes.is_open()) {
        return std::nullopt;
    }

    std::string line;
    (void)std::getline(routes, line);
    std::optional<std::uint32_t> best_hop;
    unsigned int best_prefix = 0U;
    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string device;
        std::string destination_text;
        std::string gateway_text;
        std::string flags_text;
        std::string ref_count;
        std::string use_count;
        std::string metric;
        std::string mask_text;
        if (!(fields >> device >> destination_text >> gateway_text >> flags_text >> ref_count >> use_count >> metric >>
              mask_text) ||
            device != interface_name) {
            continue;
        }

        unsigned long destination = 0UL;
        unsigned long gateway = 0UL;
        unsigned long mask = 0UL;
        unsigned long flags = 0UL;
        const auto parse_hex = [](const std::string &text, unsigned long &value) noexcept {
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
            return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
        };
        if (!parse_hex(destination_text, destination) || !parse_hex(gateway_text, gateway) ||
            !parse_hex(mask_text, mask) || !parse_hex(flags_text, flags) || destination > 0xFFFFFFFFUL ||
            gateway > 0xFFFFFFFFUL || mask > 0xFFFFFFFFUL || flags == 0UL) {
            continue;
        }

        const std::uint32_t route_destination = route_word_to_host(destination);
        const std::uint32_t route_mask = route_word_to_host(mask);
        if ((target_ipv4 & route_mask) != (route_destination & route_mask)) {
            continue;
        }
        const unsigned int prefix = static_cast<unsigned int>(__builtin_popcount(route_mask));
        if (!best_hop.has_value() || prefix > best_prefix) {
            const std::uint32_t route_gateway = route_word_to_host(gateway);
            best_hop = route_gateway == 0U ? target_ipv4 : route_gateway;
            best_prefix = prefix;
        }
    }
    return best_hop;
}

} // namespace

std::optional<std::array<std::uint8_t, 6U>> detail::cached_ipv6_neighbor_mac(
    std::string_view interface_name, const core::IpAddress &target_ip)
{
    if (!target_ip.is_ipv6() || interface_name.empty() ||
        (target_ip.is_ipv6_link_local() &&
         !core::ipv6_scope_matches_interface(target_ip, interface_name))) {
        return std::nullopt;
    }
    return ipv6_neighbor_mac_for(interface_name, target_ip.bytes);
}

std::optional<CorrelationKey> tcp_correlation_key(
    const portscan::PortSubmission &submission,
    std::uint32_t interface_index,
    std::uint64_t scan_generation)
{
    if (interface_index == 0U || scan_generation == 0U ||
        !submission.target_ip.valid() || !submission.source_ip.valid() ||
        submission.target_ip.family != submission.source_ip.family ||
        (submission.probe != portscan::ScanProbeType::TcpSyn &&
         submission.probe != portscan::ScanProbeType::TcpAck)) {
        return std::nullopt;
    }
    const auto &ip = submission.target_ip;
    const std::uint32_t ipv4 = ip.is_ipv4()
        ? (static_cast<std::uint32_t>(ip.bytes[0]) << 24U) |
          (static_cast<std::uint32_t>(ip.bytes[1]) << 16U) |
          (static_cast<std::uint32_t>(ip.bytes[2]) << 8U) | ip.bytes[3]
        : 0U;
    return CorrelationKey{ipv4, submission.source_port, submission.port.number,
                          submission.sequence_number, ip, submission.source_ip,
                          PacketProtocol::TCP, interface_index, scan_generation};
}

bool matches_tcp_reply(
    const portscan::PortSubmission &submission,
    const PacketObservation &observation) noexcept
{
    if (!observation.valid() || !observation.tcp.has_value()) {
        return false;
    }
    core::IpAddress source;
    core::IpAddress destination;
    if (observation.ipv4.has_value() && !observation.ipv6.has_value()) {
        source = core::IpAddress::from_ipv4(observation.ipv4->source_address());
        destination = core::IpAddress::from_ipv4(observation.ipv4->destination_address());
    } else if (observation.ipv6.has_value() && !observation.ipv4.has_value()) {
        source = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        destination = core::IpAddress::from_ipv6(observation.ipv6->destination_address());
    } else {
        return false;
    }
    // The capture interface owns the IPv6 scope; compare on-wire family and bytes.
    if (source.family != submission.target_ip.family || destination.family != submission.source_ip.family ||
        source.bytes != submission.target_ip.bytes || destination.bytes != submission.source_ip.bytes) {
        return false;
    }
    const packet::TCP &tcp = *observation.tcp;
    if (tcp.source_port() != submission.port.number || tcp.destination_port() != submission.source_port) {
        return false;
    }
    const bool ack = packet::has_flag(tcp.flags(), packet::TcpFlag::Ack);
    const bool rst = packet::has_flag(tcp.flags(), packet::TcpFlag::Rst);
    const bool syn = packet::has_flag(tcp.flags(), packet::TcpFlag::Syn);
    const bool fin = packet::has_flag(tcp.flags(), packet::TcpFlag::Fin);
    if (submission.probe == portscan::ScanProbeType::TcpAck) {
        // RFC 9293 section 3.10.7: a reset responding to ACK uses SEG.ACK as SEQ.
        return rst && !ack && !syn && !fin && tcp.sequence_number() == submission.acknowledgment_number;
    }
    if (submission.probe == portscan::ScanProbeType::TcpSyn) {
        return !fin && ((syn && !rst && ack && tcp.acknowledgment_number() == submission.sequence_number + 1U) ||
                        (rst && !syn && (!ack || tcp.acknowledgment_number() == submission.sequence_number + 1U)));
    }
    return false;
}

std::optional<std::vector<std::uint8_t>> tcp_response_bytes(const PacketObservation &observation)
{
    if (!observation.valid() || !observation.tcp || !observation.ethernet) { return std::nullopt; }
    std::size_t offset = packet::Ethernet::kHeaderSize + (observation.vlan_tci ? 4U : 0U);
    std::size_t length = 0U;
    if (observation.ipv4 && !observation.ipv6) {
        const std::size_t header = static_cast<std::size_t>(observation.ipv4->ihl()) * 4U;
        if (observation.ipv4->protocol() != kTcpProtocol || observation.ipv4->total_length() < header) { return std::nullopt; }
        offset += header;
        length = observation.ipv4->total_length() - header;
    } else if (observation.ipv6 && !observation.ipv4) {
        const auto &extensions = observation.ipv6_extensions;
        if (extensions.terminal_next_header != kTcpProtocol ||
            extensions.consumed_bytes > observation.ipv6->payload_length()) { return std::nullopt; }
        offset += packet::IPv6::kHeaderSize + extensions.consumed_bytes;
        length = observation.ipv6->payload_length() - extensions.consumed_bytes;
    } else { return std::nullopt; }
    if (length < packet::TCP::kMinimumHeaderSize || offset > observation.raw_frame.size() ||
        length > observation.raw_frame.size() - offset) { return std::nullopt; }
    // The parser has already checked this exact segment's framing and checksum.
    // Reconstructing its lossy option model can discard unknown options/EOL padding.
    const auto wire = std::span<const std::uint8_t>{observation.raw_frame}.subspan(offset, length);
    return std::vector<std::uint8_t>{wire.begin(), wire.end()};
}

bool matches_tcp_unreachable(
    const portscan::PortSubmission &submission,
    const PacketObservation &observation) noexcept
{
    if (!observation.valid() || submission.packet.size() < 20U ||
        (submission.probe != portscan::ScanProbeType::TcpSyn && submission.probe != portscan::ScanProbeType::TcpAck)) {
        return false;
    }
    std::span<const std::uint8_t> quote;
    std::size_t header_size = 0U;
    if (observation.ipv4.has_value() && !observation.ipv6.has_value() && observation.icmp.has_value() &&
        submission.source_ip.is_ipv4() && submission.target_ip.is_ipv4()) {
        if (observation.icmp->type() != packet::IcmpType::DestinationUnreachable || observation.icmp->code() > 15U ||
            core::IpAddress::from_ipv4(observation.ipv4->destination_address()).bytes != submission.source_ip.bytes) {
            return false;
        }
        quote = observation.icmp->payload();
        header_size = 20U;
        // Emitted probes have no IP options or fragments. ICMP may quote only eight TCP bytes;
        // the full-packet IPv4 parser intentionally does not accept that truncation.
        if (quote.size() < header_size + 8U || quote[0] != 0x45U || quote[9] != kTcpProtocol ||
            packet::wire::read_u16(quote, 2U) != header_size + submission.packet.size() ||
            (packet::wire::read_u16(quote, 6U) & 0xbfffU) != 0U ||
            packet::checksum::internet(quote.first(header_size)) != 0U ||
            core::IpAddress::from_ipv4(packet::wire::read_u32(quote, 12U)).bytes != submission.source_ip.bytes ||
            core::IpAddress::from_ipv4(packet::wire::read_u32(quote, 16U)).bytes != submission.target_ip.bytes) {
            return false;
        }
    } else if (observation.ipv6.has_value() && !observation.ipv4.has_value() && observation.icmpv6.has_value() &&
               submission.source_ip.is_ipv6() && submission.target_ip.is_ipv6()) {
        if (observation.icmpv6->type() != packet::Icmpv6Type::DestinationUnreachable || observation.icmpv6->code() > 6U ||
            observation.ipv6->destination_address() != submission.source_ip.bytes) {
            return false;
        }
        quote = observation.icmpv6->payload();
        header_size = 40U;
        // This transport emits base-header IPv6 probes, never extensions or fragments.
        if (quote.size() < header_size + 8U || (quote[0] >> 4U) != 6U || quote[6] != kTcpProtocol ||
            packet::wire::read_u16(quote, 4U) != submission.packet.size() ||
            !std::equal(submission.source_ip.bytes.begin(), submission.source_ip.bytes.end(), quote.begin() + 8U) ||
            !std::equal(submission.target_ip.bytes.begin(), submission.target_ip.bytes.end(), quote.begin() + 24U)) {
            return false;
        }
    } else {
        return false;
    }
    const auto tcp = quote.subspan(header_size);
    const std::size_t size = std::min(tcp.size(), submission.packet.size());
    for (std::size_t index = 0U; index < size; ++index) {
        // The transport recomputes the checksum with the selected source address.
        if (index != 16U && index != 17U && tcp[index] != submission.packet[index]) {
            return false;
        }
    }
    return true;
}

std::optional<portscan::ScanReason> classify_tcp_unreachable_reason(
    const PacketObservation &observation) noexcept
{
    if (observation.icmp.has_value() &&
        observation.icmp->type() == packet::IcmpType::DestinationUnreachable) {
        switch (observation.icmp->code()) {
        case 0U:
        case 1U:
        case 5U:
        case 6U:
        case 7U:
            return portscan::ScanReason::IcmpNetworkUnreachable;
        case 2U:
            return portscan::ScanReason::IcmpProtocolUnreachable;
        case 3U:
            return portscan::ScanReason::IcmpPortUnreachable;
        case 9U:
        case 10U:
        case 13U:
            return portscan::ScanReason::IcmpAdministrativelyProhibited;
        default:
            return std::nullopt;
        }
    }
    if (observation.icmpv6.has_value() &&
        observation.icmpv6->type() == packet::Icmpv6Type::DestinationUnreachable) {
        switch (observation.icmpv6->code()) {
        case 0U:
        case 2U:
        case 3U:
            return portscan::ScanReason::IcmpNetworkUnreachable;
        case 1U:
        case 5U:
        case 6U:
            return portscan::ScanReason::IcmpAdministrativelyProhibited;
        case 4U:
            return portscan::ScanReason::IcmpPortUnreachable;
        default:
            return std::nullopt;
        }
    }
    return std::nullopt;
}

const char *network_scan_status_name(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return "success";
    case NetworkScanStatus::InvalidConfiguration:
        return "invalid-configuration";
    case NetworkScanStatus::InterfaceNotFound:
        return "interface-not-found";
    case NetworkScanStatus::RoutingUnavailable:
        return "routing-unavailable";
    case NetworkScanStatus::PermissionDenied:
        return "permission-denied";
    case NetworkScanStatus::NotSupported:
        return "not-supported";
    case NetworkScanStatus::NotOpen:
        return "not-open";
    case NetworkScanStatus::SystemError:
        return "system-error";
    }
    return "unknown";
}

LinuxNetworkScanTransport::LinuxNetworkScanTransport(io::IOEngine &io_engine, NetworkScanConfig config)
    : io_engine_(io_engine),
      config_(std::move(config)),
      receiver_(capture_, config_.max_frame_size)
{
}

LinuxNetworkScanTransport::~LinuxNetworkScanTransport()
{
    close();
}

NetworkScanResult LinuxNetworkScanTransport::open()
{
    close();
    if (config_.interface_name.empty() || config_.max_frame_size == 0U) {
        return {NetworkScanStatus::InvalidConfiguration, 0, "explicit interface and positive frame limit are required"};
    }
    const InterfaceResult interface_result = find_interface_result(config_.interface_name);
    if (!interface_result.success()) {
        return {interface_result.status == InterfaceStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : interface_result.status == InterfaceStatus::NotSupported
                          ? NetworkScanStatus::NotSupported
                          : interface_result.status == InterfaceStatus::InterfaceNotFound
                                ? NetworkScanStatus::InterfaceNotFound
                                : NetworkScanStatus::SystemError,
                interface_result.system_error,
                interface_result.message};
    }
    if (interface_result.interface.ipv4_addresses.empty() && interface_result.interface.ipv6_addresses.empty()) {
        TransportPreflightResult preflight;
        preflight.category = PreflightCategory::NoSourceAddress;
        preflight.message = "selected interface has no IPv4 or IPv6 source address";
        return preflight_failure(preflight);
    }
    const core::AddressFamily startup_family = !interface_result.interface.ipv4_addresses.empty()
                                                   ? core::AddressFamily::IPv4
                                                   : core::AddressFamily::IPv6;
    const TransportPreflightResult startup_preflight = preflight_interface(
        config_.interface_name, startup_family, false, true);
    if (!startup_preflight.success()) {
        return preflight_failure(startup_preflight);
    }
    const auto mac = local_mac_for(config_.interface_name);
    if (!mac.has_value()) {
        return {NetworkScanStatus::NotSupported, errno, "local interface MAC address is unavailable"};
    }
    std::copy(mac->begin(), mac->end(), local_mac_.begin());
    source_ipv4_ = 0U;
    if (!interface_result.interface.ipv4_addresses.empty()) {
        const auto &address = interface_result.interface.ipv4_addresses.front().ipv4;
        source_ipv4_ = (static_cast<std::uint32_t>(address[0]) << 24U) |
                       (static_cast<std::uint32_t>(address[1]) << 16U) |
                       (static_cast<std::uint32_t>(address[2]) << 8U) |
                       static_cast<std::uint32_t>(address[3]);
    }
    source_ipv6_.reset();
    if (!interface_result.interface.ipv6_addresses.empty()) {
        source_ipv6_ = interface_result.interface.ipv6_addresses.front().address;
    }

    const CaptureResult capture_result = receiver_.open(CaptureConfig{
        config_.interface_name, config_.max_frame_size, config_.nonblocking});
    if (!capture_result.success()) {
        return {capture_result.status == CaptureStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : capture_result.status == CaptureStatus::InterfaceNotFound
                          ? NetworkScanStatus::InterfaceNotFound
                          : capture_result.status == CaptureStatus::NotSupported
                                ? NetworkScanStatus::NotSupported
                                : NetworkScanStatus::SystemError,
                capture_result.system_error,
                capture_result.message};
    }
    const TransportResult transport_result = transport_.open(
        TransportConfig{config_.interface_name, config_.nonblocking});
    if (!transport_result.success()) {
        receiver_.close();
        return {map_transport_status(transport_result.status), transport_result.system_error, transport_result.message};
    }
    const core::StatusCode attach_status = receiver_.attach(
        io_engine_, [this](io::Event &event) { on_capture_event(event); });
    if (attach_status != core::StatusCode::Ok) {
        transport_.close();
        receiver_.close();
        return {NetworkScanStatus::SystemError, 0, "capture descriptor registration failed"};
    }
    session_ = ScanSession{};
    session_.id = next_session_id_++;
    session_.interface = interface_result.interface;
    session_.started_at = std::chrono::steady_clock::now();
    session_.active = true;
    session_.transport_status = TransportStatus::Success;
    session_.capture_status = CaptureStatus::Success;
    session_.last_preflight_category = PreflightCategory::Ready;
    session_.last_preflight_family = startup_family;
    session_.last_system_error = 0;
    session_.last_error.clear();
    return {NetworkScanStatus::Success, 0, {}};
}

void LinuxNetworkScanTransport::close() noexcept
{
    pending_.clear();
    correlation_.clear();
    receiver_.close();
    transport_.close();
    session_.active = false;
    session_.transport_status = TransportStatus::Closed;
    session_.capture_status = CaptureStatus::Closed;
}

bool LinuxNetworkScanTransport::is_open() const noexcept
{
    return session_.active && transport_.is_open() && receiver_.is_open();
}

bool LinuxNetworkScanTransport::supports(portscan::ScanProbeType probe) const noexcept
{
    return is_open() && (probe == portscan::ScanProbeType::TcpSyn ||
                         probe == portscan::ScanProbeType::TcpAck);
}

core::StatusCode LinuxNetworkScanTransport::submit(
    const portscan::PortSubmission &submission,
    portscan::PortResponseCallback callback)
{
    if (!is_open()) {
        return core::StatusCode::PermissionDenied;
    }
    if (submission.id == 0U ||
        (submission.probe != portscan::ScanProbeType::TcpSyn &&
         submission.probe != portscan::ScanProbeType::TcpAck) || !callback ||
        submission.target.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    if (pending_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    const auto parsed_target = core::parse_ip_address(submission.target);
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : parsed_target.value_or(core::IpAddress{});
    if (!target_ip.valid()) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    const TransportPreflightResult target_preflight = preflight_interface(
        config_.interface_name, target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6, true, true);
    if (!target_preflight.success()) {
        ++session_.failed;
        session_.last_preflight_category = target_preflight.category;
        session_.last_preflight_family = target_preflight.family;
        session_.last_system_error = target_preflight.system_error;
        session_.last_error = target_preflight.message;
        return core::StatusCode::PermissionDenied;
    }
    portscan::PortSubmission effective = submission;
    effective.target_ip = target_ip;
    const auto selected_source = source_address_for(target_ip);
    if (!selected_source.has_value()) {
        ++session_.failed;
        session_.last_preflight_category = PreflightCategory::NoSourceAddress;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = 0;
        session_.last_error = "no compatible source address for target family";
        return core::StatusCode::PermissionDenied;
    }
    effective.source_ip = *selected_source;
    const auto frame = compose_frame(effective);
    if (!frame.has_value()) {
        ++session_.failed;
        session_.last_preflight_category = PreflightCategory::CapabilityUnavailable;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = 0;
        session_.last_error = "unable to construct a family-correct Ethernet/IP/TCP frame";
        return core::StatusCode::PermissionDenied;
    }
    const auto correlation_key = tcp_correlation_key(effective, session_.interface.index, session_.id);
    if (!correlation_key.has_value()) {
        ++session_.failed;
        trace("correlation reject id={} field=bound-context", effective.id);
        return core::StatusCode::InvalidArgument;
    }
    if (log::minimum_level() == log::Level::Debug) {
        try {
            trace("correlation submission id={} AF={} local={}:{} remote={}:{} interface={} seq={} ack={} scope={} scan-generation={} probe-generation=not-implemented lifecycle=pending",
                  effective.id, target_ip.is_ipv4() ? "ipv4" : "ipv6", effective.source_ip.to_string(),
                  effective.source_port, target_ip.to_string(), effective.port.number, config_.interface_name,
                  effective.sequence_number, effective.acknowledgment_number, target_ip.scope.value_or("none"), session_.id);
        } catch (...) { }
    }
    if (correlation_.insert(
            *correlation_key,
            effective.id,
            std::chrono::steady_clock::time_point::max()) != CorrelationStatus::Inserted) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    try {
        pending_.emplace(effective.id, Pending{effective, std::move(callback), *correlation_key});
    } catch (const std::bad_alloc &) {
        correlation_.remove(*correlation_key);
        ++session_.failed;
        return core::StatusCode::MemoryError;
    }
    const TransportResult send_result = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!send_result.success()) {
        correlation_.remove(*correlation_key);
        pending_.erase(submission.id);
        ++session_.failed;
        session_.transport_status = send_result.status;
        session_.last_preflight_category = send_result.status == TransportStatus::PermissionDenied
                                                ? PreflightCategory::InjectionUnavailable
                                                : PreflightCategory::Ready;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = send_result.system_error;
        session_.last_error = send_result.message;
        return map_network_status(map_transport_status(send_result.status));
    }
    ++session_.submitted;
    trace("correlation sent id={} bytes={}", effective.id, frame->size());
    return core::StatusCode::Ok;
}

core::StatusCode LinuxNetworkScanTransport::cancel(portscan::PortProbeId id) noexcept
{
    const auto found = pending_.find(id);
    if (found != pending_.end()) {
        trace("correlation cancel id={} lifecycle=retired observed={}", id, found->second.observed);
        correlation_.remove(found->second.correlation_key);
        if (found->second.failed) {
            ++session_.failed;
        } else if (found->second.observed) {
            ++session_.completed;
        } else {
            ++session_.timed_out;
        }
        pending_.erase(found);
    }
    return core::StatusCode::Ok;
}

const ScanSession &LinuxNetworkScanTransport::session() const noexcept
{
    return session_;
}

int LinuxNetworkScanTransport::transport_file_descriptor() const noexcept
{
    return transport_.file_descriptor();
}

int LinuxNetworkScanTransport::capture_file_descriptor() const noexcept
{
    return capture_.file_descriptor();
}

void LinuxNetworkScanTransport::on_capture_event(io::Event &event) noexcept
{
    (void)event;
    if (!is_open()) {
        return;
    }
    try {
        for (std::size_t index = 0U; index < kMaximumCaptureBatch && is_open(); ++index) {
            const ReceiverResult received = receiver_.receive();
            if (received.capture.status == CaptureStatus::WouldBlock) {
                session_.capture_status = CaptureStatus::Success;
                return;
            }
            if (received.capture.status != CaptureStatus::Success) {
                session_.capture_status = received.capture.status;
                if (received.capture.status == CaptureStatus::Empty ||
                    received.capture.status == CaptureStatus::OversizedFrame) {
                    return;
                }
                session_.last_system_error = received.capture.system_error;
                session_.last_error = received.capture.message;
                while (!pending_.empty()) {
                    const auto current = pending_.begin();
                    const portscan::PortProbeId id = current->first;
                    current->second.failed = true;
                    portscan::PortResponse response;
                    response.id = id;
                    response.source_address = current->second.submission.target;
                    response.kind = portscan::PortResponseKind::SocketError;
                    response.system_error = received.capture.system_error;
                    response.received_at = std::chrono::steady_clock::now();
                    response.reason = portscan::ScanReason::SocketError;
                    portscan::PortResponseCallback callback = current->second.callback;
                    callback(response);
                    const auto still_pending = pending_.find(id);
                    if (still_pending != pending_.end()) {
                        correlation_.remove(still_pending->second.correlation_key);
                        ++session_.failed;
                        pending_.erase(still_pending);
                    }
                }
                return;
            }
            session_.capture_status = CaptureStatus::Success;
            if (received.observation.has_value()) {
                trace("correlation parser status={} bytes={}", parse_status_name(received.observation->status),
                      received.observation->raw_frame.size());
                dispatch_observation(*received.observation);
            }
        }
    } catch (...) {
        session_.capture_status = CaptureStatus::ReceiveFailed;
    }
}

std::optional<portscan::PortProbeId> detail::resolve_tcp_response(
    const PacketObservation &observation,
    const TcpPendingMap &pending,
    CorrelationTable &correlation,
    std::uint32_t interface_index,
    std::uint64_t scan_generation)
{
    if (!observation.valid() || interface_index == 0U || scan_generation == 0U) {
        trace("correlation reject field={}", !observation.valid() ? "parser" : "bound-context");
        return std::nullopt;
    }
    const bool unreachable = observation.icmp.has_value() || observation.icmpv6.has_value();
    const auto admitted = [&](portscan::PortProbeId id, const TcpPendingCorrelation &candidate) {
        const auto &submission = candidate.submission;
        if (submission.id != id) {
            trace("correlation reject id={} field=probe-id", id);
            return false;
        }
        if (unreachable ? !matches_tcp_unreachable(submission, observation)
                        : !matches_tcp_reply(submission, observation)) {
            trace("correlation reject id={} field={}", id,
                  unreachable ? "quoted-identity" : reply_mismatch(submission, observation));
            return false;
        }
        if (candidate.correlation_key.scan_generation != scan_generation) {
            trace("correlation reject id={} field=scan-generation", id);
            return false;
        }
        if (candidate.correlation_key.interface_index != interface_index) {
            trace("correlation reject id={} field=interface", id);
            return false;
        }
        const auto found = correlation.lookup(candidate.correlation_key, observation.received_at);
        if (found.status != CorrelationStatus::Found || !found.entry || found.entry->token != id) {
            trace("correlation reject id={} field=registry-lifecycle status={}", id,
                  static_cast<int>(found.status));
            return false;
        }
        return true;
    };

    // Preserve the indexed IPv4 SYN/ACK path. A miss never falls back to a
    // less-specific tuple; all candidates still undergo the strict validator.
    if (!unreachable && observation.ipv4 && !observation.ipv6 && observation.tcp &&
        packet::has_flag(observation.tcp->flags(), packet::TcpFlag::Ack)) {
        const auto &tcp = *observation.tcp;
        portscan::PortSubmission identity;
        identity.probe = portscan::ScanProbeType::TcpSyn;
        identity.target_ip = core::IpAddress::from_ipv4(observation.ipv4->source_address());
        identity.source_ip = core::IpAddress::from_ipv4(observation.ipv4->destination_address());
        identity.source_port = tcp.destination_port();
        identity.port.number = tcp.source_port();
        identity.sequence_number = tcp.acknowledgment_number() - 1U;
        const auto key = tcp_correlation_key(identity, interface_index, scan_generation);
        if (!key) { return std::nullopt; }
        const auto found = correlation.lookup(*key, observation.received_at);
        trace("correlation lookup remote={} local-port={} remote-port={} seq={} status={}",
              key->target_ipv4, key->source_port, key->destination_port, key->sequence,
              static_cast<int>(found.status));
        if (found.status == CorrelationStatus::Found && found.entry) {
            const auto candidate = pending.find(found.entry->token);
            if (candidate != pending.end() && admitted(candidate->first, candidate->second)) {
                return candidate->first;
            }
        }
        if (log::minimum_level() == log::Level::Debug) {
            for (const auto &[id, candidate] : pending) {
                trace("correlation unmatched id={} field={}", id,
                      matches_tcp_reply(candidate.submission, observation)
                          ? "key/lifecycle" : reply_mismatch(candidate.submission, observation));
            }
        }
        return std::nullopt;
    }

    std::optional<portscan::PortProbeId> matched;
    for (const auto &[id, candidate] : pending) {
        if (!admitted(id, candidate)) { continue; }
        if (matched) {
            trace("correlation reject field=lifecycle-ambiguous ids={},{}", *matched, id);
            return std::nullopt;
        }
        matched = id;
    }
    return matched;
}

void LinuxNetworkScanTransport::dispatch_observation(const PacketObservation &observation) noexcept
{
    try {
        // This adapter owns the context: received packets cannot choose it.
        if (observation.ipv4 && observation.tcp &&
            observation.ipv4->destination_address() != source_ipv4_) {
            trace("correlation reject field=dst-IP interface={}", config_.interface_name);
            return;
        }
        const auto matched = detail::resolve_tcp_response(
            observation, pending_, correlation_, session_.interface.index, session_.id);
        if (!matched) { return; }
        const auto pending = pending_.find(*matched);
        if (pending == pending_.end()) { return; }
        portscan::PortResponse response;
        response.id = *matched;
        response.received_at = observation.received_at;
        if (observation.ipv4) {
            response.source_ip = core::IpAddress::from_ipv4(observation.ipv4->source_address());
        } else if (observation.ipv6) {
            response.source_ip = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        }
        if (observation.icmp || observation.icmpv6) {
            const auto reason = classify_tcp_unreachable_reason(observation);
            if (!reason) { return; }
            response.kind = portscan::PortResponseKind::Unreachable;
            response.reason = *reason;
        } else {
            auto bytes = tcp_response_bytes(observation);
            if (!bytes) {
                trace("correlation reject id={} field=wire-bounds", *matched);
                return;
            }
            response.kind = portscan::PortResponseKind::Packet;
            response.bytes = std::move(*bytes);
            response.source_ip.scope = pending->second.submission.target_ip.scope;
            trace("correlation admitted id={} TCP-seq={} TCP-ack={} lifecycle=pending",
                  *matched, observation.tcp->sequence_number(), observation.tcp->acknowledgment_number());
        }
        response.source_address = response.source_ip.to_string();
        pending->second.observed = true;
        auto callback = pending->second.callback;
        callback(response);
    } catch (...) {
        session_.capture_status = CaptureStatus::ReceiveFailed;
        trace("correlation reject field=receive-exception");
    }
}

std::optional<std::vector<std::uint8_t>> LinuxNetworkScanTransport::compose_frame(
    const portscan::PortSubmission &submission) const
{
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : core::parse_ip_address(submission.target).value_or(core::IpAddress{});
    if (!target_ip.valid() || !submission.source_ip.valid()) {
        return std::nullopt;
    }
    const auto tcp = packet::TCP::parse(std::span<const std::uint8_t>{submission.packet});
    if (!tcp.has_value()) {
        return std::nullopt;
    }
    const auto destination = destination_mac(target_ip);
    if (!destination.has_value()) {
        return std::nullopt;
    }
    packet::Packet packet;
    std::optional<packet::TCP> wire_tcp;
    if (target_ip.is_ipv4() && submission.source_ip.is_ipv4()) {
        const std::uint32_t target_ipv4 = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                          static_cast<std::uint32_t>(target_ip.bytes[3]);
        const std::uint32_t source_ipv4 = (static_cast<std::uint32_t>(submission.source_ip.bytes[0]) << 24U) |
                                          (static_cast<std::uint32_t>(submission.source_ip.bytes[1]) << 16U) |
                                          (static_cast<std::uint32_t>(submission.source_ip.bytes[2]) << 8U) |
                                          static_cast<std::uint32_t>(submission.source_ip.bytes[3]);
        packet::IPv4 ipv4;
        ipv4.set_protocol(kTcpProtocol);
        ipv4.set_source_address(source_ipv4);
        ipv4.set_destination_address(target_ipv4);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, kEtherTypeIpv4));
        packet.set_ipv4(ipv4);
        std::vector<std::uint8_t> tcp_bytes(tcp->serialized_size(), 0U);
        if (tcp->serialize_with_checksum(
                std::span<std::uint8_t>{tcp_bytes}, source_ipv4, target_ipv4,
                std::span<const std::uint8_t>{tcp->payload()}) != core::StatusCode::Ok) {
            return std::nullopt;
        }
        wire_tcp = packet::TCP::parse(std::span<const std::uint8_t>{tcp_bytes});
    } else if (target_ip.is_ipv6() && submission.source_ip.is_ipv6()) {
        packet::IPv6 ipv6;
        ipv6.set_next_header(kTcpProtocol);
        ipv6.set_source_address(submission.source_ip.bytes);
        ipv6.set_destination_address(target_ip.bytes);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, 0x86DDU));
        packet.set_ipv6(ipv6);
        std::vector<std::uint8_t> tcp_bytes(tcp->serialized_size(), 0U);
        if (tcp->serialize_with_checksum(
                std::span<std::uint8_t>{tcp_bytes}, submission.source_ip.bytes, target_ip.bytes,
                std::span<const std::uint8_t>{tcp->payload()}) != core::StatusCode::Ok) {
            return std::nullopt;
        }
        wire_tcp = packet::TCP::parse(std::span<const std::uint8_t>{tcp_bytes});
    } else {
        return std::nullopt;
    }
    if (!wire_tcp.has_value()) {
        return std::nullopt;
    }
    packet.set_tcp(*wire_tcp);
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

std::optional<std::array<std::uint8_t, 6U>> LinuxNetworkScanTransport::destination_mac(
    std::uint32_t target_ipv4) const
{
    if (config_.destination_mac.has_value()) {
        return config_.destination_mac;
    }
    if (config_.interface_name == "lo") {
        return std::array<std::uint8_t, 6U>{};
    }
    const auto next_hop = ipv4_next_hop_for(config_.interface_name, target_ipv4);
    if (!next_hop.has_value()) {
        return std::nullopt;
    }
    return neighbor_mac_for(config_.interface_name, *next_hop);
}

std::optional<std::array<std::uint8_t, 6U>> LinuxNetworkScanTransport::destination_mac(
    const core::IpAddress &target_ip) const
{
    if (target_ip.is_ipv4()) {
        const std::uint32_t address = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                      static_cast<std::uint32_t>(target_ip.bytes[3]);
        return destination_mac(address);
    }
    if (config_.destination_mac.has_value()) {
        return config_.destination_mac;
    }
    if (config_.interface_name == "lo") {
        return std::array<std::uint8_t, 6U>{};
    }
    return detail::cached_ipv6_neighbor_mac(config_.interface_name, target_ip);
}

std::optional<core::IpAddress> LinuxNetworkScanTransport::source_address_for(
    const core::IpAddress &target_ip) const
{
    if (target_ip.is_ipv4()) {
        return source_ipv4_ == 0U ? std::nullopt : std::optional<core::IpAddress>{core::IpAddress::from_ipv4(source_ipv4_)};
    }
    if (!source_ipv6_.has_value()) {
        return std::nullopt;
    }
    core::IpAddress source = *source_ipv6_;
    if (target_ip.is_ipv6_link_local()) {
        if (!core::ipv6_scope_matches_interface(target_ip, config_.interface_name)) {
            return std::nullopt;
        }
        source.scope = target_ip.scope;
    }
    return source;
}

} // namespace skan::net
