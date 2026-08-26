#include "net/interface.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <map>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sstream>
#include <span>
#include <unistd.h>
#include <utility>

namespace skan::net {
namespace {

std::uint8_t prefix_length(const sockaddr_in *netmask) noexcept
{
    if (netmask == nullptr) {
        return 0U;
    }
    const std::uint32_t mask = ntohl(netmask->sin_addr.s_addr);
    std::uint8_t prefix = 0U;
    for (int bit = 31; bit >= 0; --bit) {
        if ((mask & (static_cast<std::uint32_t>(1U) << static_cast<unsigned int>(bit))) == 0U) {
            break;
        }
        ++prefix;
    }
    return prefix;
}

std::uint8_t prefix_length(const sockaddr_in6 *netmask) noexcept
{
    if (netmask == nullptr) {
        return 0U;
    }
    std::uint8_t prefix = 0U;
    for (const std::uint8_t byte : std::span<const std::uint8_t>{netmask->sin6_addr.s6_addr, 16U}) {
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte & (static_cast<std::uint8_t>(1U) << static_cast<unsigned int>(bit))) == 0U) {
                return prefix;
            }
            ++prefix;
        }
    }
    return prefix;
}

void add_ipv4_address(NetworkInterface &interface, const ifaddrs *address)
{
    if (address == nullptr || address->ifa_addr == nullptr || address->ifa_addr->sa_family != AF_INET) {
        return;
    }
    const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address->ifa_addr);
    InterfaceAddress value;
    std::memcpy(value.ipv4.data(), &ipv4->sin_addr.s_addr, value.ipv4.size());
    const auto *netmask = reinterpret_cast<const sockaddr_in *>(address->ifa_netmask);
    value.prefix_length = prefix_length(netmask);
    if (std::find(interface.ipv4_addresses.begin(), interface.ipv4_addresses.end(), value) ==
        interface.ipv4_addresses.end()) {
        interface.ipv4_addresses.push_back(value);
    }
}

void add_ipv6_address(NetworkInterface &interface, const ifaddrs *address)
{
    if (address == nullptr || address->ifa_addr == nullptr || address->ifa_addr->sa_family != AF_INET6 ||
        address->ifa_name == nullptr || address->ifa_name[0] == '\0') {
        return;
    }
    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(address->ifa_addr);
    std::array<std::uint8_t, 16U> bytes{};
    std::memcpy(bytes.data(), ipv6->sin6_addr.s6_addr, bytes.size());
    InterfaceIPv6Address value;
    value.address = core::IpAddress::from_ipv6(bytes);
    if (value.address.is_ipv6_link_local()) {
        value.address.scope = std::string(address->ifa_name);
    }
    const auto *netmask = reinterpret_cast<const sockaddr_in6 *>(address->ifa_netmask);
    value.prefix_length = prefix_length(netmask);
    if (std::find(interface.ipv6_addresses.begin(), interface.ipv6_addresses.end(), value) ==
        interface.ipv6_addresses.end()) {
        interface.ipv6_addresses.push_back(value);
    }
}

struct InterfaceCapabilities final {
    bool raw_packet{false};
    bool af_inet{false};
    bool af_inet6{false};
    int raw_diagnostic{0};
    int inet_diagnostic{0};
    int inet6_diagnostic{0};
};

bool is_ipv6_loopback(const core::IpAddress &address) noexcept
{
    if (!address.is_ipv6()) {
        return false;
    }
    for (std::size_t index = 0U; index < address.bytes.size() - 1U; ++index) {
        if (address.bytes[index] != 0U) {
            return false;
        }
    }
    return address.bytes.back() == 1U;
}

CapabilityFact capability(
    CapabilityState state,
    const NetworkInterface &interface,
    core::AddressFamily family,
    std::string reason,
    int diagnostic = 0)
{
    return {state, interface.name, family, std::move(reason), diagnostic};
}

bool has_ipv4_route(std::string_view interface_name)
{
    std::ifstream routes("/proc/net/route");
    if (!routes.is_open()) {
        return false;
    }
    std::string line;
    (void)std::getline(routes, line);
    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string device;
        std::string destination;
        std::string gateway;
        std::string flags;
        if (fields >> device >> destination >> gateway >> flags && device == interface_name && flags != "0") {
            return true;
        }
    }
    return false;
}

bool has_ipv6_route(std::string_view interface_name)
{
    std::ifstream routes("/proc/net/ipv6_route");
    if (!routes.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string destination;
        std::string destination_prefix;
        std::string source;
        std::string source_prefix;
        std::string next_hop;
        std::string metric;
        std::string reference;
        std::string use;
        std::string flags;
        std::string device;
        if (fields >> destination >> destination_prefix >> source >> source_prefix >> next_hop >> metric >> reference >> use >> flags >> device &&
            device == interface_name) {
            return true;
        }
    }
    return false;
}

InterfaceCapabilities probe_capabilities(std::uint32_t index) noexcept
{
    InterfaceCapabilities result;
    if (index == 0U) {
        return result;
    }
    const int inet_descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (inet_descriptor >= 0) {
        result.af_inet = true;
        (void)::close(inet_descriptor);
    } else {
        result.inet_diagnostic = errno;
    }
    const int inet6_descriptor = ::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (inet6_descriptor >= 0) {
        result.af_inet6 = true;
        (void)::close(inet6_descriptor);
    } else {
        result.inet6_diagnostic = errno;
    }
    const int descriptor = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (descriptor < 0) {
        result.raw_diagnostic = errno;
        return result;
    }
    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(index);
    result.raw_packet = ::bind(
                           descriptor,
                           reinterpret_cast<const sockaddr *>(&address),
                           sizeof(address)) == 0;
    if (!result.raw_packet) {
        result.raw_diagnostic = errno;
    }
    (void)::close(descriptor);
    return result;
}

} // namespace

InterfaceEnumerationResult enumerate_interfaces_result()
{
    InterfaceEnumerationResult result;
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) {
        result.status = InterfaceStatus::EnumerationFailed;
        result.system_error = errno;
        result.message = std::strerror(result.system_error);
        return result;
    }

    std::map<std::string, NetworkInterface> by_name;
    for (const ifaddrs *address = addresses; address != nullptr; address = address->ifa_next) {
        if (address->ifa_name == nullptr || address->ifa_name[0] == '\0') {
            continue;
        }
        const std::string name{address->ifa_name};
        NetworkInterface &interface = by_name[name];
        interface.name = name;
        interface.index = if_nametoindex(address->ifa_name);
        interface.is_up = interface.is_up || ((address->ifa_flags & IFF_UP) != 0U);
        add_ipv4_address(interface, address);
        add_ipv6_address(interface, address);
    }
    ::freeifaddrs(addresses);

    for (auto &[name, interface] : by_name) {
        (void)name;
        const InterfaceCapabilities capabilities = probe_capabilities(interface.index);
        const bool has_ipv4_address = !interface.ipv4_addresses.empty();
        const bool has_ipv6_address = !interface.ipv6_addresses.empty();
        const bool has_global_ipv6 = std::any_of(
            interface.ipv6_addresses.begin(), interface.ipv6_addresses.end(),
            [](const InterfaceIPv6Address &address) {
                return !address.address.is_ipv6_link_local() && !is_ipv6_loopback(address.address);
            });
        const bool has_link_local_ipv6 = std::any_of(
            interface.ipv6_addresses.begin(), interface.ipv6_addresses.end(),
            [](const InterfaceIPv6Address &address) { return address.address.is_ipv6_link_local(); });
        const bool ipv4_route = has_ipv4_address && has_ipv4_route(interface.name);
        const bool ipv6_route = has_ipv6_address && has_ipv6_route(interface.name);
        const std::string raw_reason = capabilities.raw_packet
                                           ? "AF_PACKET socket and interface bind succeeded"
                                           : std::strerror(capabilities.raw_diagnostic);
        const std::string inet_reason = capabilities.af_inet
                                            ? "AF_INET datagram socket succeeded"
                                            : std::strerror(capabilities.inet_diagnostic);
        const std::string inet6_reason = capabilities.af_inet6
                                             ? "AF_INET6 datagram socket succeeded"
                                             : std::strerror(capabilities.inet6_diagnostic);
        interface.supports_capture = capabilities.raw_packet;
        interface.supports_injection = capabilities.raw_packet;
        interface.supports_af_inet6 = capabilities.af_inet6;
        interface.supports_ipv6_route = ipv6_route;
        interface.has_cap_net_raw = capabilities.raw_packet;
        interface.supports_ipv6_capture = capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address;
        interface.supports_ipv6_injection = interface.supports_ipv6_capture;
        interface.af_inet = capability(
            capabilities.af_inet ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4, inet_reason, capabilities.inet_diagnostic);
        interface.ipv4_route = capability(
            ipv4_route ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4,
            ipv4_route ? "IPv4 route entry is present" : (has_ipv4_address ? "no IPv4 route entry" : "no IPv4 source address"));
        interface.ipv4_source = capability(
            has_ipv4_address ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4,
            has_ipv4_address ? "IPv4 source address is assigned to the interface" : "no IPv4 source address");
        interface.raw_ipv4_capture = capability(
            capabilities.raw_packet ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4, raw_reason, capabilities.raw_diagnostic);
        interface.raw_ipv4_injection = capability(
            capabilities.raw_packet ? CapabilityState::Unknown : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4,
            capabilities.raw_packet ? "AF_PACKET bind succeeded; packet injection was not exercised safely"
                                     : "AF_PACKET bind is unavailable",
            capabilities.raw_diagnostic);
        const bool ipv4_probe_prerequisites = capabilities.raw_packet && capabilities.af_inet && has_ipv4_address;
        interface.tcp_syn_ipv4 = capability(
            ipv4_probe_prerequisites ? CapabilityState::Unknown : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4,
            ipv4_probe_prerequisites ? "raw TCP SYN prerequisites exist; destination validation is target-specific"
                                     : "IPv4 raw TCP SYN prerequisites are unavailable",
            capabilities.raw_diagnostic);
        interface.udp_raw_ipv4 = capability(
            ipv4_probe_prerequisites ? CapabilityState::Unknown : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv4,
            ipv4_probe_prerequisites ? "raw UDP prerequisites exist; destination validation is target-specific"
                                     : "IPv4 raw UDP prerequisites are unavailable",
            capabilities.raw_diagnostic);
        interface.icmp_ipv4 = interface.raw_ipv4_capture;
        interface.af_inet6 = capability(
            capabilities.af_inet6 ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6, inet6_reason, capabilities.inet6_diagnostic);
        interface.ipv6_route = capability(
            ipv6_route ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            ipv6_route ? "IPv6 route entry is present" : (has_ipv6_address ? "no IPv6 route entry" : "no IPv6 address"));
        interface.global_ipv6_source = capability(
            has_global_ipv6 ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            has_global_ipv6 ? "global IPv6 source address is assigned" : "no global IPv6 source address");
        interface.link_local_ipv6_source = capability(
            has_link_local_ipv6 ? CapabilityState::Available : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            has_link_local_ipv6 ? "link-local IPv6 source address is assigned" : "no link-local IPv6 source address");
        interface.raw_ipv6_capture = capability(
            capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address ? CapabilityState::Available
                                                                                   : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address
                ? "AF_PACKET bind and IPv6 address prerequisites are available"
                : "AF_PACKET bind, AF_INET6, or IPv6 address prerequisite is unavailable",
            capabilities.raw_diagnostic);
        interface.raw_ipv6_injection = capability(
            capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address ? CapabilityState::Unknown
                                                                                   : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address
                ? "AF_PACKET bind succeeded; IPv6 packet injection was not exercised safely"
                : "AF_PACKET bind, AF_INET6, or IPv6 address prerequisite is unavailable",
            capabilities.raw_diagnostic);
        interface.icmpv6 = interface.raw_ipv6_capture;
        const bool ipv6_probe_prerequisites = capabilities.raw_packet && capabilities.af_inet6 && has_ipv6_address && ipv6_route;
        interface.tcp_syn_ipv6 = capability(
            ipv6_probe_prerequisites ? CapabilityState::Unknown : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            ipv6_probe_prerequisites ? "raw IPv6 TCP SYN prerequisites exist; destination validation is target-specific"
                                     : "IPv6 raw TCP SYN prerequisites are unavailable",
            capabilities.raw_diagnostic);
        interface.udp_ipv6 = interface.tcp_syn_ipv6;
        const bool ndp_prerequisites = capabilities.raw_packet && capabilities.af_inet6 && has_link_local_ipv6;
        interface.ndp_ipv6 = capability(
            ndp_prerequisites ? CapabilityState::Unknown : CapabilityState::Unavailable,
            interface, core::AddressFamily::IPv6,
            ndp_prerequisites ? "link-local NDP prerequisites exist; neighbor exchange was not exercised safely"
                              : "IPv6 link-local NDP prerequisites are unavailable",
            capabilities.raw_diagnostic);
        std::sort(interface.ipv4_addresses.begin(), interface.ipv4_addresses.end(),
                  [](const InterfaceAddress &left, const InterfaceAddress &right) {
                      if (left.ipv4 != right.ipv4) {
                          return left.ipv4 < right.ipv4;
                      }
                      return left.prefix_length < right.prefix_length;
                  });
        std::sort(interface.ipv6_addresses.begin(), interface.ipv6_addresses.end(),
                  [](const InterfaceIPv6Address &left, const InterfaceIPv6Address &right) {
                      if (left.address != right.address) {
                          return left.address < right.address;
                      }
                      return left.prefix_length < right.prefix_length;
                  });
        result.interfaces.push_back(std::move(interface));
    }
    result.status = InterfaceStatus::Success;
    return result;
}

std::vector<NetworkInterface> enumerate_interfaces()
{
    return enumerate_interfaces_result().interfaces;
}

InterfaceResult find_interface_result(std::string_view name)
{
    InterfaceResult result;
    if (name.empty()) {
        result.status = InterfaceStatus::InvalidName;
        result.message = "interface name is required";
        return result;
    }
    const InterfaceEnumerationResult enumeration = enumerate_interfaces_result();
    if (!enumeration.success()) {
        result.status = enumeration.status;
        result.system_error = enumeration.system_error;
        result.message = enumeration.message;
        return result;
    }
    const auto found = std::find_if(
        enumeration.interfaces.begin(), enumeration.interfaces.end(),
        [name](const NetworkInterface &interface) { return interface.name == name; });
    if (found == enumeration.interfaces.end()) {
        result.status = InterfaceStatus::InterfaceNotFound;
        result.message = "interface was not found";
        return result;
    }
    result.interface = *found;
    result.status = InterfaceStatus::Success;
    return result;
}

std::optional<NetworkInterface> find_interface(std::string_view name)
{
    InterfaceResult result = find_interface_result(name);
    if (!result.success()) {
        return std::nullopt;
    }
    return result.interface;
}

} // namespace skan::net
