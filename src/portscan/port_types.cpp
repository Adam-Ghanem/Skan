#include "portscan/port_types.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <string_view>

namespace skan::portscan {
namespace {

std::string_view trim(std::string_view value) noexcept
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1U);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1U);
    }
    return value;
}

bool parse_port_number(std::string_view value, std::uint16_t &port) noexcept
{
    value = trim(value);
    if (value.empty()) {
        return false;
    }
    unsigned int parsed_value = 0U;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed_value, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed_value == 0U ||
        parsed_value > 65535U) {
        return false;
    }
    port = static_cast<std::uint16_t>(parsed_value);
    return true;
}

} // namespace

PortSelection parse_tcp_ports(std::string_view specification)
{
    PortSelection selection;
    if (trim(specification).empty()) {
        selection.status = core::StatusCode::InvalidArgument;
        return selection;
    }

    try {
        std::size_t start = 0U;
        while (start <= specification.size()) {
            const std::size_t comma = specification.find(',', start);
            const std::size_t end = comma == std::string_view::npos ? specification.size() : comma;
            std::string_view token = trim(specification.substr(start, end - start));
            if (token.empty()) {
                selection.status = core::StatusCode::InvalidArgument;
                selection.ports.clear();
                return selection;
            }

            const std::size_t dash = token.find('-');
            if (dash == std::string_view::npos) {
                std::uint16_t port = 0U;
                if (!parse_port_number(token, port)) {
                    selection.status = core::StatusCode::InvalidArgument;
                    selection.ports.clear();
                    return selection;
                }
                selection.ports.push_back(Port{port, Protocol::Tcp});
            } else {
                if (token.find('-', dash + 1U) != std::string_view::npos) {
                    selection.status = core::StatusCode::InvalidArgument;
                    selection.ports.clear();
                    return selection;
                }
                std::uint16_t first = 0U;
                std::uint16_t last = 0U;
                if (!parse_port_number(token.substr(0U, dash), first) ||
                    !parse_port_number(token.substr(dash + 1U), last) || first > last) {
                    selection.status = core::StatusCode::InvalidArgument;
                    selection.ports.clear();
                    return selection;
                }
                for (std::uint32_t port = first; port <= last; ++port) {
                    selection.ports.push_back(Port{static_cast<std::uint16_t>(port), Protocol::Tcp});
                }
            }

            if (comma == std::string_view::npos) {
                break;
            }
            start = comma + 1U;
        }
        std::sort(selection.ports.begin(), selection.ports.end());
        selection.ports.erase(
            std::unique(selection.ports.begin(), selection.ports.end()), selection.ports.end());
    } catch (const std::bad_alloc &) {
        selection.status = core::StatusCode::MemoryError;
        selection.ports.clear();
    }
    return selection;
}

std::vector<Port> default_tcp_ports()
{
    return {{22U, Protocol::Tcp}, {kDefaultTcpPort, Protocol::Tcp}, {443U, Protocol::Tcp}};
}

const char *protocol_name(Protocol protocol) noexcept
{
    switch (protocol) {
    case Protocol::Tcp:
        return "tcp";
    default:
        return "unknown";
    }
}

const char *scan_probe_type_name(ScanProbeType probe) noexcept
{
    switch (probe) {
    case ScanProbeType::TcpConnect:
        return "connect";
    case ScanProbeType::TcpSyn:
        return "syn";
    default:
        return "unknown";
    }
}

const char *port_state_name(PortState state) noexcept
{
    switch (state) {
    case PortState::Open:
        return "OPEN";
    case PortState::Closed:
        return "CLOSED";
    case PortState::Filtered:
        return "FILTERED";
    case PortState::Unknown:
        return "UNKNOWN";
    default:
        return "UNKNOWN";
    }
}

const char *scan_reason_name(ScanReason reason) noexcept
{
    switch (reason) {
    case ScanReason::ImmediateSuccess:
        return "IMMEDIATE_SUCCESS";
    case ScanReason::ConnectionRefused:
        return "CONNECTION_REFUSED";
    case ScanReason::SynAck:
        return "SYN_ACK";
    case ScanReason::Rst:
        return "RST";
    case ScanReason::Timeout:
        return "TIMEOUT";
    case ScanReason::SocketError:
        return "SOCKET_ERROR";
    case ScanReason::MalformedResponse:
        return "MALFORMED_RESPONSE";
    case ScanReason::UnrelatedResponse:
        return "UNRELATED_RESPONSE";
    case ScanReason::UnauthorizedTarget:
        return "UNAUTHORIZED_TARGET";
    case ScanReason::InvalidTarget:
        return "INVALID_TARGET";
    case ScanReason::InvalidPort:
        return "INVALID_PORT";
    case ScanReason::UnsupportedMethod:
        return "UNSUPPORTED_METHOD";
    case ScanReason::CapabilityUnavailable:
        return "CAPABILITY_UNAVAILABLE";
    case ScanReason::InternalError:
        return "INTERNAL_ERROR";
    default:
        return "UNKNOWN";
    }
}

} // namespace skan::portscan
