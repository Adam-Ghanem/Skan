#include "output/output_writer.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace skan::output {
namespace {

bool port_less(const portscan::PortResult &left, const portscan::PortResult &right) noexcept
{
    if (left.port.number != right.port.number) {
        return left.port.number < right.port.number;
    }
    if (left.port.protocol != right.port.protocol) {
        return static_cast<unsigned int>(left.port.protocol) < static_cast<unsigned int>(right.port.protocol);
    }
    return left.target < right.target;
}

bool service_less(const detect::ServiceResult &left, const detect::ServiceResult &right) noexcept
{
    if (left.port.number != right.port.number) {
        return left.port.number < right.port.number;
    }
    if (left.protocol != right.protocol) {
        return static_cast<unsigned int>(left.protocol) < static_cast<unsigned int>(right.protocol);
    }
    if (left.target != right.target) {
        return left.target < right.target;
    }
    if (left.probe_name != right.probe_name) {
        return left.probe_name < right.probe_name;
    }
    if (left.service != right.service) {
        return left.service < right.service;
    }
    if (left.product != right.product) {
        return left.product < right.product;
    }
    if (left.version != right.version) {
        return left.version < right.version;
    }
    return left.confidence > right.confidence;
}

bool os_less(const osdetect::OSMatchResult &left, const osdetect::OSMatchResult &right) noexcept
{
    if (left.confidence != right.confidence) {
        return left.confidence > right.confidence;
    }
    return left.fingerprint_name < right.fingerprint_name;
}

bool host_less(const HostResult &left, const HostResult &right) noexcept
{
    return left.address < right.address;
}

} // namespace

namespace detail {

std::vector<const HostResult *> ordered_hosts(const ScanReport &report)
{
    std::vector<const HostResult *> hosts;
    hosts.reserve(report.hosts.size());
    for (const HostResult &host : report.hosts) {
        hosts.push_back(&host);
    }
    std::sort(hosts.begin(), hosts.end(), [](const HostResult *left, const HostResult *right) {
        return host_less(*left, *right);
    });
    return hosts;
}

std::vector<const portscan::PortResult *> ordered_ports(const HostResult &host, const OutputContext &context)
{
    std::vector<const portscan::PortResult *> ports;
    ports.reserve(host.ports.size());
    for (const portscan::PortResult &port : host.ports) {
        if (context.open_only && port.state != portscan::PortState::Open &&
            port.state != portscan::PortState::OpenOrFiltered) {
            continue;
        }
        if (port.state == portscan::PortState::Closed && !context.include_closed_ports) {
            continue;
        }
        if ((port.state == portscan::PortState::Filtered || port.state == portscan::PortState::OpenOrFiltered) &&
            !context.include_filtered_ports) {
            continue;
        }
        if (port.state == portscan::PortState::Unknown && !context.include_unknown) {
            continue;
        }
        ports.push_back(&port);
    }
    std::sort(ports.begin(), ports.end(), [](const portscan::PortResult *left, const portscan::PortResult *right) {
        return port_less(*left, *right);
    });
    return ports;
}

std::vector<const detect::ServiceResult *> ordered_services(const HostResult &host)
{
    std::vector<const detect::ServiceResult *> services;
    services.reserve(host.services.size());
    for (const detect::ServiceResult &service : host.services) {
        services.push_back(&service);
    }
    std::sort(services.begin(), services.end(), [](const detect::ServiceResult *left,
                                                   const detect::ServiceResult *right) {
        return service_less(*left, *right);
    });
    return services;
}

std::vector<const osdetect::OSMatchResult *> ordered_os_matches(const HostResult &host)
{
    std::vector<const osdetect::OSMatchResult *> matches;
    matches.reserve(host.os_matches.size());
    for (const osdetect::OSMatchResult &match : host.os_matches) {
        matches.push_back(&match);
    }
    std::sort(matches.begin(), matches.end(), [](const osdetect::OSMatchResult *left,
                                                 const osdetect::OSMatchResult *right) {
        return os_less(*left, *right);
    });
    return matches;
}

std::string json_escape(std::string_view value)
{
    std::string escaped;
    escaped.reserve(value.size());
    static constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char character : value) {
        switch (character) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (character < 0x20U) {
                escaped += "\\u00";
                escaped.push_back(hex[(character >> 4U) & 0x0fU]);
                escaped.push_back(hex[character & 0x0fU]);
            } else {
                escaped.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    return escaped;
}

std::string xml_escape(std::string_view value)
{
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        switch (character) {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '"':
            escaped += "&quot;";
            break;
        case '\'':
            escaped += "&apos;";
            break;
        default:
            if (static_cast<unsigned char>(character) < 0x20U && character != '\n' && character != '\r' &&
                character != '\t') {
                escaped.push_back('?');
            } else {
                escaped.push_back(character);
            }
            break;
        }
    }
    return escaped;
}

std::string grep_escape(std::string_view value)
{
    std::string escaped;
    escaped.reserve(value.size());
    for (const unsigned char character : value) {
        if (character == '\\' || character == '"' || character == '\n' || character == '\r' ||
            character == '\t') {
            escaped.push_back('\\');
            if (character == '\n') {
                escaped.push_back('n');
            } else if (character == '\r') {
                escaped.push_back('r');
            } else if (character == '\t') {
                escaped.push_back('t');
            } else {
                escaped.push_back(static_cast<char>(character));
            }
        } else if (character < 0x20U || character == 0x7fU) {
            escaped.push_back('?');
        } else {
            escaped.push_back(static_cast<char>(character));
        }
    }
    return escaped;
}

std::string number(double value)
{
    std::ostringstream stream;
    stream << std::setprecision(15) << value;
    return stream.str();
}

OutputStatus check_stream(std::ostream &output) noexcept
{
    return output.good() ? OutputStatus::Ok : OutputStatus::IoError;
}

} // namespace detail

} // namespace skan::output
