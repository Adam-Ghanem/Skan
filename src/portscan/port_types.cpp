#include "portscan/port_types.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <new>
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

PortSelection parse_ports(std::string_view specification, Protocol protocol)
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
            const std::string_view token = trim(specification.substr(start, end - start));
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
                selection.ports.push_back(Port{port, protocol});
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
                    selection.ports.push_back(Port{static_cast<std::uint16_t>(port), protocol});
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

} // namespace

PortSelection parse_tcp_ports(std::string_view specification)
{
    return parse_ports(specification, Protocol::Tcp);
}

PortSelection parse_udp_ports(std::string_view specification)
{
    return parse_ports(specification, Protocol::Udp);
}

std::vector<Port> default_tcp_ports()
{
    return {{22U, Protocol::Tcp}, {kDefaultTcpPort, Protocol::Tcp}, {443U, Protocol::Tcp}};
}

std::vector<Port> default_udp_ports()
{
    return {
        {53U, Protocol::Udp},
        {67U, Protocol::Udp},
        {68U, Protocol::Udp},
        {69U, Protocol::Udp},
        {123U, Protocol::Udp},
        {137U, Protocol::Udp},
        {161U, Protocol::Udp},
        {162U, Protocol::Udp},
        {500U, Protocol::Udp},
        {514U, Protocol::Udp}};
}

const char *protocol_name(Protocol protocol) noexcept
{
    switch (protocol) {
    case Protocol::Tcp:
        return "tcp";
    case Protocol::Udp:
        return "udp";
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
    case ScanProbeType::Udp:
        return "udp";
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
    case PortState::OpenOrFiltered:
        return "OPEN_OR_FILTERED";
    case PortState::Unfiltered:
        return "UNFILTERED";
    case PortState::Error:
        return "ERROR";
    case PortState::Unreachable:
        return "UNREACHABLE";
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
    case ScanReason::NetworkUnreachable:
        return "NETWORK_UNREACHABLE";
    case ScanReason::LocalAddressUnavailable:
        return "LOCAL_ADDRESS_UNAVAILABLE";
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
    case ScanReason::UdpResponse:
        return "UDP_RESPONSE";
    case ScanReason::IcmpPortUnreachable:
        return "ICMP_PORT_UNREACHABLE";
    case ScanReason::IcmpAdministrativelyProhibited:
        return "ICMP_ADMINISTRATIVELY_PROHIBITED";
    case ScanReason::IcmpNetworkUnreachable:
        return "ICMP_NETWORK_UNREACHABLE";
    case ScanReason::UdpTimeout:
        return "UDP_TIMEOUT";
    case ScanReason::DuplicateResponse:
        return "DUPLICATE_RESPONSE";
    case ScanReason::LateResponse:
        return "LATE_RESPONSE";
    case ScanReason::UnsupportedProtocol:
        return "UNSUPPORTED_PROTOCOL";
    default:
        return "UNKNOWN";
    }
}

} // namespace skan::portscan
