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
    bool af_inet6{false};
};

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
    const int inet6_descriptor = ::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (inet6_descriptor >= 0) {
        result.af_inet6 = true;
        (void)::close(inet6_descriptor);
    }
    const int descriptor = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (descriptor < 0) {
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
        interface.supports_capture = capabilities.raw_packet;
        interface.supports_injection = capabilities.raw_packet;
        interface.supports_af_inet6 = capabilities.af_inet6;
        interface.supports_ipv6_route = !interface.ipv6_addresses.empty() && has_ipv6_route(interface.name);
        interface.has_cap_net_raw = capabilities.raw_packet;
        interface.supports_ipv6_capture = capabilities.raw_packet && capabilities.af_inet6 &&
                                           !interface.ipv6_addresses.empty();
        interface.supports_ipv6_injection = interface.supports_ipv6_capture;
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
