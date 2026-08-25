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
    PermissionDenied,
    NotSupported,
    SystemError
};

const char *interface_status_name(InterfaceStatus status) noexcept;

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
