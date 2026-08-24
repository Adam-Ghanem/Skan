#ifndef SKAN_DISCOVERY_DISCOVERY_TYPES_HPP
#define SKAN_DISCOVERY_DISCOVERY_TYPES_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/types.hpp"

namespace skan::discovery {

inline constexpr std::uint16_t kDefaultTcpDiscoveryPort = 80U;
inline constexpr std::chrono::milliseconds kDefaultDiscoveryTimeout{1000};
inline constexpr std::size_t kDefaultMaxOutstanding = 64U;

enum class HostState {
    Unknown = 0,
    Up,
    Down
};

enum class ProbeType {
    IcmpEcho = 0,
    Tcp,
    Arp
};

enum class DiscoveryReason {
    NoEvidence = 0,
    IcmpEchoReply,
    TcpSynAck,
    TcpRst,
    ArpReply,
    Timeout,
    InvalidTarget,
    UnsupportedInterface,
    SocketFailure,
    PermissionFailure,
    MalformedResponse,
    UnexpectedResponse,
    DuplicateResponse,
    LateResponse,
    InternalError
};

using ProbeId = std::uint64_t;
using DiscoveryClock = std::chrono::steady_clock;
using DiscoveryTimePoint = DiscoveryClock::time_point;

struct DiscoveryResult final {
    std::string target;
    HostState state{HostState::Unknown};
    ProbeType probe{ProbeType::IcmpEcho};
    bool responded{false};
    std::optional<double> rtt_ms;
    DiscoveryTimePoint timestamp{};
    DiscoveryReason reason{DiscoveryReason::NoEvidence};
};

struct DiscoveryConfig final {
    std::vector<ProbeType> probes{ProbeType::IcmpEcho, ProbeType::Tcp};
    std::uint16_t tcp_port{kDefaultTcpDiscoveryPort};
    std::chrono::milliseconds timeout{kDefaultDiscoveryTimeout};
    std::size_t max_outstanding{kDefaultMaxOutstanding};
};

struct DiscoveryResponse final {
    ProbeId probe_id{0U};
    std::string source_address;
    std::vector<std::uint8_t> bytes;
    DiscoveryTimePoint received_at{};
};

const char *host_state_name(HostState state) noexcept;
const char *probe_type_name(ProbeType probe) noexcept;
const char *discovery_reason_name(DiscoveryReason reason) noexcept;

/** Convert one dotted-decimal IPv4 address to network-order integer form. */
std::optional<std::uint32_t> parse_ipv4_address(std::string_view address) noexcept;

} // namespace skan::discovery

#endif // SKAN_DISCOVERY_DISCOVERY_TYPES_HPP
