#ifndef SKAN_PORTSCAN_PORT_TYPES_HPP
#define SKAN_PORTSCAN_PORT_TYPES_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "core/status.hpp"
#include "scanengine/timing_profile.hpp"

namespace skan::portscan {

enum class Protocol {
    Tcp = 0,
    Udp
};

enum class ScanProbeType {
    TcpConnect = 0,
    TcpSyn,
    Udp
};

enum class PortState {
    Open = 0,
    Closed,
    Filtered,
    Unknown,
    OpenOrFiltered,
    Unfiltered,
    Error,
    Unreachable
};

enum class ScanReason {
    ImmediateSuccess = 0,
    ConnectionRefused,
    NetworkUnreachable,
    LocalAddressUnavailable,
    SynAck,
    Rst,
    Timeout,
    SocketError,
    MalformedResponse,
    UnrelatedResponse,
    InvalidTarget,
    InvalidPort,
    UnsupportedMethod,
    CapabilityUnavailable,
    InternalError,
    UdpResponse,
    IcmpPortUnreachable,
    IcmpAdministrativelyProhibited,
    IcmpNetworkUnreachable,
    UdpTimeout,
    DuplicateResponse,
    LateResponse,
    UnsupportedProtocol
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
inline constexpr std::size_t kDefaultUdpMaxOutstanding = 64U;
inline constexpr std::chrono::milliseconds kDefaultUdpTimeout{1500};
inline constexpr std::size_t kDefaultUdpRetries = 1U;

struct PortScanConfig final {
    ScanProbeType method{ScanProbeType::TcpConnect};
    std::chrono::milliseconds timeout{kDefaultPortTimeout};
    std::size_t max_outstanding{kDefaultMaxOutstanding};
    bool adaptive_timing{false};
    scanengine::TimingProfile timing_profile{};
    std::size_t retries{0U};
};

struct PortSelection final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<Port> ports;
};

PortSelection parse_tcp_ports(std::string_view specification);
PortSelection parse_udp_ports(std::string_view specification);
std::vector<Port> default_tcp_ports();
std::vector<Port> default_udp_ports();

const char *protocol_name(Protocol protocol) noexcept;
const char *scan_probe_type_name(ScanProbeType probe) noexcept;
const char *port_state_name(PortState state) noexcept;
const char *scan_reason_name(ScanReason reason) noexcept;

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_PORT_TYPES_HPP
