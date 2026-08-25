#ifndef SKAN_CORE_TYPES_HPP
#define SKAN_CORE_TYPES_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace skan::core {

enum class AddressFamily : std::uint8_t {
    Unknown = 0,
    IPv4,
    IPv6
};

struct IpAddress final {
    AddressFamily family{AddressFamily::Unknown};
    std::array<std::uint8_t, 16U> bytes{};

    static IpAddress from_ipv4(std::uint32_t address) noexcept;
    static IpAddress from_ipv6(const std::array<std::uint8_t, 16U> &address) noexcept;

    bool is_ipv4() const noexcept { return family == AddressFamily::IPv4; }
    bool is_ipv6() const noexcept { return family == AddressFamily::IPv6; }
    bool valid() const noexcept { return is_ipv4() || is_ipv6(); }
    std::string to_string() const;

    friend bool operator==(const IpAddress &, const IpAddress &) noexcept = default;
    friend bool operator<(const IpAddress &left, const IpAddress &right) noexcept;
};

struct IpAddressHash final {
    std::size_t operator()(const IpAddress &address) const noexcept;
};

const char *address_family_name(AddressFamily family) noexcept;

inline bool operator!=(const IpAddress &left, const IpAddress &right) noexcept
{
    return !(left == right);
}

enum class Protocol {
    Unknown = 0,
    Tcp,
    Udp
};

enum class PortState {
    Unknown = 0,
    Open,
    Closed,
    Filtered
};

struct Host {
    std::string address;
    std::optional<std::string> hostname;
    bool is_up{false};
    IpAddress ip_address{};
};

struct Port {
    std::uint16_t number{0};
    Protocol protocol{Protocol::Unknown};
    PortState state{PortState::Unknown};
    std::optional<std::string> service;
};

struct Target {
    std::string original_specification;
    std::vector<Host> resolved_hosts;
};

struct ScanResult {
    Host host;
    std::vector<Port> ports;
    std::optional<std::string> metadata;
};

} // namespace skan::core

#endif // SKAN_CORE_TYPES_HPP
