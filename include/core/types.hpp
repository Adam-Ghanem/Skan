#ifndef SKAN_CORE_TYPES_HPP
#define SKAN_CORE_TYPES_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace skan::core {

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
