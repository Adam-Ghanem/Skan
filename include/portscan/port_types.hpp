#ifndef SKAN_PORTSCAN_PORT_TYPES_HPP
#define SKAN_PORTSCAN_PORT_TYPES_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "core/status.hpp"

namespace skan::portscan {

enum class Protocol {
    Tcp = 0
};

enum class ScanProbeType {
    TcpConnect = 0,
    TcpSyn
};

enum class PortState {
    Open = 0,
    Closed,
    Filtered,
    Unknown
};

enum class ScanReason {
    ImmediateSuccess = 0,
    ConnectionRefused,
    SynAck,
    Rst,
    Timeout,
    SocketError,
    MalformedResponse,
    UnrelatedResponse,
    UnauthorizedTarget,
    InvalidTarget,
    InvalidPort,
    UnsupportedMethod,
    CapabilityUnavailable,
    InternalError
};

struct Port final {
    std::uint16_t number{0U};
    Protocol protocol{Protocol::Tcp};

    friend constexpr bool operator==(const Port &, const Port &) noexcept = default;
    friend constexpr bool operator<(const Port &left, const Port &right) noexcept
    {
        if (left.number != right.number) {
            return left.number < right.number;
        }
        return static_cast<unsigned int>(left.protocol) < static_cast<unsigned int>(right.protocol);
    }
};

inline constexpr std::uint16_t kDefaultTcpPort = 80U;
inline constexpr std::uint16_t kDefaultMaxTcpPort = 1024U;
inline constexpr std::size_t kDefaultMaxOutstanding = 128U;
inline constexpr std::chrono::milliseconds kDefaultPortTimeout{1000};

struct PortScanConfig final {
    ScanProbeType method{ScanProbeType::TcpConnect};
    std::chrono::milliseconds timeout{kDefaultPortTimeout};
    std::size_t max_outstanding{kDefaultMaxOutstanding};
};

struct PortSelection final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<Port> ports;
};

PortSelection parse_tcp_ports(std::string_view specification);
std::vector<Port> default_tcp_ports();

const char *protocol_name(Protocol protocol) noexcept;
const char *scan_probe_type_name(ScanProbeType probe) noexcept;
const char *port_state_name(PortState state) noexcept;
const char *scan_reason_name(ScanReason reason) noexcept;

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_PORT_TYPES_HPP
