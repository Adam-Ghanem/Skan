#ifndef SKAN_NET_INTERFACE_TYPES_HPP
#define SKAN_NET_INTERFACE_TYPES_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "core/types.hpp"

namespace skan::net {

enum class InterfaceStatus {
    Success,
    InvalidName,
    EnumerationFailed,
    InterfaceNotFound,
    RoutingUnavailable,
    PermissionDenied,
    NotSupported,
    SystemError
};

const char *interface_status_name(InterfaceStatus status) noexcept;

enum class CapabilityState : std::uint8_t {
    Available = 0,
    Unavailable,
    Unknown
};

const char *capability_state_name(CapabilityState state) noexcept;

struct CapabilityFact final {
    CapabilityState state{CapabilityState::Unknown};
    std::string interface_name;
    core::AddressFamily family{core::AddressFamily::Unknown};
    std::string reason;
    int diagnostic{0};
};

struct InterfaceAddress final {
    std::array<std::uint8_t, 4U> ipv4{};
    std::uint8_t prefix_length{0U};

    bool operator==(const InterfaceAddress &) const noexcept = default;
};

struct InterfaceIPv6Address final {
    core::IpAddress address{};
    std::uint8_t prefix_length{0U};

    bool operator==(const InterfaceIPv6Address &) const noexcept = default;
};

struct NetworkInterface final {
    std::string name;
    std::uint32_t index{0U};
    std::vector<InterfaceAddress> ipv4_addresses;
    std::vector<InterfaceIPv6Address> ipv6_addresses;
    bool is_up{false};
    bool supports_capture{false};
    bool supports_injection{false};
    bool supports_ipv6_capture{false};
    bool supports_ipv6_injection{false};
    bool supports_af_inet6{false};
    bool supports_ipv6_route{false};
    bool has_cap_net_raw{false};

    CapabilityFact af_inet;
    CapabilityFact ipv4_route;
    CapabilityFact ipv4_source;
    CapabilityFact raw_ipv4_capture;
    CapabilityFact raw_ipv4_injection;
    CapabilityFact tcp_syn_ipv4;
    CapabilityFact udp_raw_ipv4;
    CapabilityFact icmp_ipv4;
    CapabilityFact af_inet6;
    CapabilityFact ipv6_route;
    CapabilityFact global_ipv6_source;
    CapabilityFact link_local_ipv6_source;
    CapabilityFact raw_ipv6_capture;
    CapabilityFact raw_ipv6_injection;
    CapabilityFact icmpv6;
    CapabilityFact tcp_syn_ipv6;
    CapabilityFact udp_ipv6;
    CapabilityFact ndp_ipv6;
};

struct InterfaceResult final {
    InterfaceStatus status{InterfaceStatus::Success};
    int system_error{0};
    std::string message;
    NetworkInterface interface;

    bool success() const noexcept { return status == InterfaceStatus::Success; }
};

struct InterfaceEnumerationResult final {
    InterfaceStatus status{InterfaceStatus::Success};
    int system_error{0};
    std::string message;
    std::vector<NetworkInterface> interfaces;

    bool success() const noexcept { return status == InterfaceStatus::Success; }
};

} // namespace skan::net

#endif // SKAN_NET_INTERFACE_TYPES_HPP
