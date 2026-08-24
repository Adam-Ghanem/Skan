#include "discovery/discovery_types.hpp"

#include <charconv>

namespace skan::discovery {

const char *host_state_name(HostState state) noexcept
{
    switch (state) {
    case HostState::Unknown:
        return "UNKNOWN";
    case HostState::Up:
        return "UP";
    case HostState::Down:
        return "DOWN";
    default:
        return "UNKNOWN";
    }
}

const char *probe_type_name(ProbeType probe) noexcept
{
    switch (probe) {
    case ProbeType::IcmpEcho:
        return "ICMP_ECHO";
    case ProbeType::Tcp:
        return "TCP";
    case ProbeType::Arp:
        return "ARP";
    default:
        return "UNKNOWN";
    }
}

const char *discovery_reason_name(DiscoveryReason reason) noexcept
{
    switch (reason) {
    case DiscoveryReason::NoEvidence:
        return "NO_EVIDENCE";
    case DiscoveryReason::IcmpEchoReply:
        return "ICMP_ECHO_REPLY";
    case DiscoveryReason::TcpSynAck:
        return "TCP_SYN_ACK";
    case DiscoveryReason::TcpRst:
        return "TCP_RST";
    case DiscoveryReason::ArpReply:
        return "ARP_REPLY";
    case DiscoveryReason::Timeout:
        return "TIMEOUT";
    case DiscoveryReason::InvalidTarget:
        return "INVALID_TARGET";
    case DiscoveryReason::UnsupportedInterface:
        return "UNSUPPORTED_INTERFACE";
    case DiscoveryReason::SocketFailure:
        return "SOCKET_FAILURE";
    case DiscoveryReason::PermissionFailure:
        return "PERMISSION_FAILURE";
    case DiscoveryReason::MalformedResponse:
        return "MALFORMED_RESPONSE";
    case DiscoveryReason::UnexpectedResponse:
        return "UNEXPECTED_RESPONSE";
    case DiscoveryReason::DuplicateResponse:
        return "DUPLICATE_RESPONSE";
    case DiscoveryReason::LateResponse:
        return "LATE_RESPONSE";
    case DiscoveryReason::InternalError:
        return "INTERNAL_ERROR";
    default:
        return "UNKNOWN";
    }
}

std::optional<std::uint32_t> parse_ipv4_address(std::string_view address) noexcept
{
    std::uint32_t result = 0U;
    std::size_t start = 0U;
    for (std::size_t component = 0U; component < 4U; ++component) {
        const std::size_t end = address.find('.', start);
        if (component < 3U && end == std::string_view::npos) {
            return std::nullopt;
        }
        if (component == 3U && end != std::string_view::npos) {
            return std::nullopt;
        }
        const std::size_t component_end = end == std::string_view::npos ? address.size() : end;
        if (component_end == start || component_end - start > 3U) {
            return std::nullopt;
        }
        unsigned int value = 0U;
        const char *first = address.data() + static_cast<std::ptrdiff_t>(start);
        const char *last = address.data() + static_cast<std::ptrdiff_t>(component_end);
        const auto parsed = std::from_chars(first, last, value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != last || value > 255U) {
            return std::nullopt;
        }
        result = (result << 8U) | static_cast<std::uint32_t>(value);
        start = component_end + 1U;
    }
    return result;
}

} // namespace skan::discovery
