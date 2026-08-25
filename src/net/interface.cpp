#include "net/interface.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <map>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

std::pair<bool, bool> probe_capabilities(std::uint32_t index) noexcept
{
    if (index == 0U) {
        return {false, false};
    }
    const int descriptor = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (descriptor < 0) {
        return {false, false};
    }
    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(index);
    const bool available = ::bind(
                               descriptor,
                               reinterpret_cast<const sockaddr *>(&address),
                               sizeof(address)) == 0;
    const int saved_errno = errno;
    (void)::close(descriptor);
    (void)saved_errno;
    return {available, available};
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
    }
    ::freeifaddrs(addresses);

    for (auto &[name, interface] : by_name) {
        (void)name;
        const auto capabilities = probe_capabilities(interface.index);
        interface.supports_capture = capabilities.first;
        interface.supports_injection = capabilities.second;
        std::sort(interface.ipv4_addresses.begin(), interface.ipv4_addresses.end(),
                  [](const InterfaceAddress &left, const InterfaceAddress &right) {
                      if (left.ipv4 != right.ipv4) {
                          return left.ipv4 < right.ipv4;
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
