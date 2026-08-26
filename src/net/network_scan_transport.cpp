#include "net/network_scan_transport.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <new>
#include <utility>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "packet/ethernet.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/packet.hpp"
#include "packet/tcp.hpp"

namespace skan::net {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint8_t kTcpProtocol = 6U;

NetworkScanStatus map_transport_status(TransportStatus status) noexcept
{
    switch (status) {
    case TransportStatus::Success:
        return NetworkScanStatus::Success;
    case TransportStatus::InvalidConfiguration:
        return NetworkScanStatus::InvalidConfiguration;
    case TransportStatus::InterfaceNotFound:
        return NetworkScanStatus::InterfaceNotFound;
    case TransportStatus::PermissionDenied:
        return NetworkScanStatus::PermissionDenied;
    case TransportStatus::NotSupported:
        return NetworkScanStatus::NotSupported;
    case TransportStatus::NotOpen:
    case TransportStatus::Closed:
        return NetworkScanStatus::NotOpen;
    case TransportStatus::SendFailed:
    case TransportStatus::CaptureFailed:
    case TransportStatus::SystemError:
        return NetworkScanStatus::SystemError;
    }
    return NetworkScanStatus::SystemError;
}

NetworkScanResult preflight_failure(const TransportPreflightResult &preflight)
{
    const NetworkScanStatus status = preflight.category == PreflightCategory::InvalidInterface
                                         ? NetworkScanStatus::InterfaceNotFound
                                         : preflight.category == PreflightCategory::NoRoute
                                               ? NetworkScanStatus::RoutingUnavailable
                                               : preflight.category == PreflightCategory::UnsupportedFamily ||
                                                         preflight.category == PreflightCategory::MtuUnavailable
                                                     ? NetworkScanStatus::NotSupported
                                                     : NetworkScanStatus::PermissionDenied;
    NetworkScanResult result{status, preflight.system_error, preflight.message};
    result.category = preflight.category;
    result.family = preflight.family;
    return result;
}

core::StatusCode map_network_status(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return core::StatusCode::Ok;
    case NetworkScanStatus::InvalidConfiguration:
        return core::StatusCode::InvalidArgument;
    case NetworkScanStatus::InterfaceNotFound:
        return core::StatusCode::NotFound;
    case NetworkScanStatus::RoutingUnavailable:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::PermissionDenied:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::NotSupported:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::NotOpen:
    case NetworkScanStatus::SystemError:
        return core::StatusCode::IoError;
    }
    return core::StatusCode::IoError;
}

std::optional<std::array<std::uint8_t, 6U>> parse_mac(std::string_view text)
{
    std::array<std::uint8_t, 6U> mac{};
    std::size_t begin = 0U;
    for (std::size_t index = 0U; index < mac.size(); ++index) {
        const std::size_t end = text.find(':', begin);
        const std::size_t length = end == std::string_view::npos ? text.size() - begin : end - begin;
        if (length == 0U || length > 2U) {
            return std::nullopt;
        }
        unsigned int value = 0U;
        const auto parsed = std::from_chars(text.data() + static_cast<std::ptrdiff_t>(begin),
                                            text.data() + static_cast<std::ptrdiff_t>(begin + length),
                                            value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + static_cast<std::ptrdiff_t>(begin + length) ||
            value > 255U) {
            return std::nullopt;
        }
        mac[index] = static_cast<std::uint8_t>(value);
        if (index + 1U < mac.size()) {
            if (end == std::string_view::npos) {
                return std::nullopt;
            }
            begin = end + 1U;
        } else if (end != std::string_view::npos) {
            return std::nullopt;
        }
    }
    return mac;
}

std::optional<std::array<std::uint8_t, 6U>> local_mac_for(std::string_view interface_name)
{
    const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return std::nullopt;
    }
    ifreq request{};
    if (interface_name.size() >= IFNAMSIZ) {
        (void)::close(descriptor);
        return std::nullopt;
    }
    std::memcpy(request.ifr_name, interface_name.data(), interface_name.size());
    request.ifr_name[interface_name.size()] = '\0';
    if (::ioctl(descriptor, SIOCGIFHWADDR, &request) != 0) {
        (void)::close(descriptor);
        return std::nullopt;
    }
    std::array<std::uint8_t, 6U> mac{};
    std::memcpy(mac.data(), request.ifr_hwaddr.sa_data, mac.size());
    (void)::close(descriptor);
    return mac;
}

std::optional<std::array<std::uint8_t, 6U>> neighbor_mac_for(
    std::string_view interface_name,
    std::uint32_t target_ipv4)
{
    std::ifstream neighbors("/proc/net/arp");
    if (!neighbors.is_open()) {
        return std::nullopt;
    }
    std::string line;
    (void)std::getline(neighbors, line);
    while (std::getline(neighbors, line)) {
        std::istringstream fields(line);
        std::string address;
        std::string hardware_type;
        std::string flags;
        std::string hardware_address;
        std::string mask;
        std::string device;
        if (!(fields >> address >> hardware_type >> flags >> hardware_address >> mask >> device) ||
            device != interface_name) {
            continue;
        }
        in_addr parsed_address{};
        if (::inet_pton(AF_INET, address.c_str(), &parsed_address) != 1 ||
            parsed_address.s_addr != htonl(target_ipv4)) {
            continue;
        }
        return parse_mac(hardware_address);
    }
    return std::nullopt;
}

std::string ipv4_text(std::uint32_t address)
{
    in_addr value{};
    value.s_addr = htonl(address);
    char buffer[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &value, buffer, sizeof(buffer)) == nullptr) {
        return {};
    }
    return buffer;
}

} // namespace

const char *network_scan_status_name(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return "success";
    case NetworkScanStatus::InvalidConfiguration:
        return "invalid-configuration";
    case NetworkScanStatus::InterfaceNotFound:
        return "interface-not-found";
    case NetworkScanStatus::RoutingUnavailable:
        return "routing-unavailable";
    case NetworkScanStatus::PermissionDenied:
        return "permission-denied";
    case NetworkScanStatus::NotSupported:
        return "not-supported";
    case NetworkScanStatus::NotOpen:
        return "not-open";
    case NetworkScanStatus::SystemError:
        return "system-error";
    }
    return "unknown";
}

LinuxNetworkScanTransport::LinuxNetworkScanTransport(io::IOEngine &io_engine, NetworkScanConfig config)
    : io_engine_(io_engine),
      config_(std::move(config)),
      receiver_(capture_, config_.max_frame_size)
{
}

LinuxNetworkScanTransport::~LinuxNetworkScanTransport()
{
    close();
}

NetworkScanResult LinuxNetworkScanTransport::open()
{
    close();
    if (config_.interface_name.empty() || config_.max_frame_size == 0U) {
        return {NetworkScanStatus::InvalidConfiguration, 0, "explicit interface and positive frame limit are required"};
    }
    const InterfaceResult interface_result = find_interface_result(config_.interface_name);
    if (!interface_result.success()) {
        return {interface_result.status == InterfaceStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : interface_result.status == InterfaceStatus::NotSupported
                          ? NetworkScanStatus::NotSupported
                          : interface_result.status == InterfaceStatus::InterfaceNotFound
                                ? NetworkScanStatus::InterfaceNotFound
                                : NetworkScanStatus::SystemError,
                interface_result.system_error,
                interface_result.message};
    }
    if (interface_result.interface.ipv4_addresses.empty() && interface_result.interface.ipv6_addresses.empty()) {
        TransportPreflightResult preflight;
        preflight.category = PreflightCategory::NoSourceAddress;
        preflight.message = "selected interface has no IPv4 or IPv6 source address";
        return preflight_failure(preflight);
    }
    const core::AddressFamily startup_family = !interface_result.interface.ipv4_addresses.empty()
                                                   ? core::AddressFamily::IPv4
                                                   : core::AddressFamily::IPv6;
    const TransportPreflightResult startup_preflight = preflight_interface(
        config_.interface_name, startup_family, false, true);
    if (!startup_preflight.success()) {
        return preflight_failure(startup_preflight);
    }
    const auto mac = local_mac_for(config_.interface_name);
    if (!mac.has_value()) {
        return {NetworkScanStatus::NotSupported, errno, "local interface MAC address is unavailable"};
    }
    std::copy(mac->begin(), mac->end(), local_mac_.begin());
    source_ipv4_ = 0U;
    if (!interface_result.interface.ipv4_addresses.empty()) {
        const auto &address = interface_result.interface.ipv4_addresses.front().ipv4;
        source_ipv4_ = (static_cast<std::uint32_t>(address[0]) << 24U) |
                       (static_cast<std::uint32_t>(address[1]) << 16U) |
                       (static_cast<std::uint32_t>(address[2]) << 8U) |
                       static_cast<std::uint32_t>(address[3]);
    }
    source_ipv6_.reset();
    if (!interface_result.interface.ipv6_addresses.empty()) {
        source_ipv6_ = interface_result.interface.ipv6_addresses.front().address;
    }

    const CaptureResult capture_result = receiver_.open(CaptureConfig{
        config_.interface_name, config_.max_frame_size, config_.nonblocking});
    if (!capture_result.success()) {
        return {capture_result.status == CaptureStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : capture_result.status == CaptureStatus::InterfaceNotFound
                          ? NetworkScanStatus::InterfaceNotFound
                          : capture_result.status == CaptureStatus::NotSupported
                                ? NetworkScanStatus::NotSupported
                                : NetworkScanStatus::SystemError,
                capture_result.system_error,
                capture_result.message};
    }
    const TransportResult transport_result = transport_.open(
        TransportConfig{config_.interface_name, config_.nonblocking});
    if (!transport_result.success()) {
        receiver_.close();
        return {map_transport_status(transport_result.status), transport_result.system_error, transport_result.message};
    }
    const core::StatusCode attach_status = receiver_.attach(
        io_engine_, [this](io::Event &event) { on_capture_event(event); });
    if (attach_status != core::StatusCode::Ok) {
        transport_.close();
        receiver_.close();
        return {NetworkScanStatus::SystemError, 0, "capture descriptor registration failed"};
    }
    session_ = ScanSession{};
    session_.id = next_session_id_++;
    session_.interface = interface_result.interface;
    session_.started_at = std::chrono::steady_clock::now();
    session_.active = true;
    session_.transport_status = TransportStatus::Success;
    session_.capture_status = CaptureStatus::Success;
    session_.last_preflight_category = PreflightCategory::Ready;
    session_.last_preflight_family = startup_family;
    session_.last_system_error = 0;
    session_.last_error.clear();
    return {NetworkScanStatus::Success, 0, {}};
}

void LinuxNetworkScanTransport::close() noexcept
{
    pending_.clear();
    correlation_.clear();
    receiver_.close();
    transport_.close();
    session_.active = false;
    session_.transport_status = TransportStatus::Closed;
    session_.capture_status = CaptureStatus::Closed;
}

bool LinuxNetworkScanTransport::is_open() const noexcept
{
    return session_.active && transport_.is_open() && receiver_.is_open();
}

bool LinuxNetworkScanTransport::supports(portscan::ScanProbeType probe) const noexcept
{
    return is_open() && probe == portscan::ScanProbeType::TcpSyn;
}

core::StatusCode LinuxNetworkScanTransport::submit(
    const portscan::PortSubmission &submission,
    portscan::PortResponseCallback callback)
{
    if (!is_open()) {
        return core::StatusCode::PermissionDenied;
    }
    if (submission.id == 0U || submission.probe != portscan::ScanProbeType::TcpSyn || !callback ||
        submission.target.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    if (pending_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    const auto parsed_target = core::parse_ip_address(submission.target);
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : parsed_target.value_or(core::IpAddress{});
    if (!target_ip.valid()) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    const TransportPreflightResult target_preflight = preflight_interface(
        config_.interface_name, target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6, true, true);
    if (!target_preflight.success()) {
        ++session_.failed;
        session_.last_preflight_category = target_preflight.category;
        session_.last_preflight_family = target_preflight.family;
        session_.last_system_error = target_preflight.system_error;
        session_.last_error = target_preflight.message;
        return target_preflight.category == PreflightCategory::NoRoute ? core::StatusCode::PermissionDenied
                                                                        : core::StatusCode::PermissionDenied;
    }
    portscan::PortSubmission effective = submission;
    effective.target_ip = target_ip;
    const auto selected_source = source_address_for(target_ip);
    if (!selected_source.has_value()) {
        ++session_.failed;
        session_.last_preflight_category = PreflightCategory::NoSourceAddress;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = 0;
        session_.last_error = "no compatible source address for target family";
        return core::StatusCode::PermissionDenied;
    }
    effective.source_ip = *selected_source;
    const auto frame = compose_frame(effective);
    if (!frame.has_value()) {
        ++session_.failed;
        session_.last_preflight_category = PreflightCategory::CapabilityUnavailable;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = 0;
        session_.last_error = "unable to construct a family-correct Ethernet/IP/TCP frame";
        return core::StatusCode::PermissionDenied;
    }
    const std::uint32_t target_ipv4 = target_ip.is_ipv4()
                                          ? ((static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                             (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                             (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                             static_cast<std::uint32_t>(target_ip.bytes[3]))
                                          : 0U;
    const CorrelationKey correlation_key{
        target_ipv4,
        effective.source_port,
        effective.port.number,
        effective.sequence_number,
        target_ip};
    if (correlation_.insert(
            correlation_key,
            effective.id,
            std::chrono::steady_clock::time_point::max()) != CorrelationStatus::Inserted) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    try {
        pending_.emplace(effective.id, Pending{effective, std::move(callback), correlation_key});
    } catch (const std::bad_alloc &) {
        correlation_.remove(correlation_key);
        ++session_.failed;
        return core::StatusCode::MemoryError;
    }
    const TransportResult send_result = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!send_result.success()) {
        correlation_.remove(correlation_key);
        pending_.erase(submission.id);
        ++session_.failed;
        session_.transport_status = send_result.status;
        session_.last_preflight_category = send_result.status == TransportStatus::PermissionDenied
                                                ? PreflightCategory::InjectionUnavailable
                                                : PreflightCategory::Ready;
        session_.last_preflight_family = target_ip.is_ipv4() ? core::AddressFamily::IPv4 : core::AddressFamily::IPv6;
        session_.last_system_error = send_result.system_error;
        session_.last_error = send_result.message;
        return map_network_status(map_transport_status(send_result.status));
    }
    ++session_.submitted;
    return core::StatusCode::Ok;
}

core::StatusCode LinuxNetworkScanTransport::cancel(portscan::PortProbeId id) noexcept
{
    const auto found = pending_.find(id);
    if (found != pending_.end()) {
        correlation_.remove(found->second.correlation_key);
        pending_.erase(found);
        ++session_.timed_out;
    }
    return core::StatusCode::Ok;
}

const ScanSession &LinuxNetworkScanTransport::session() const noexcept
{
    return session_;
}

int LinuxNetworkScanTransport::transport_file_descriptor() const noexcept
{
    return transport_.file_descriptor();
}

int LinuxNetworkScanTransport::capture_file_descriptor() const noexcept
{
    return capture_.file_descriptor();
}

void LinuxNetworkScanTransport::on_capture_event(io::Event &event) noexcept
{
    (void)event;
    if (!is_open()) {
        return;
    }
    try {
        const ReceiverResult received = receiver_.receive();
        if (received.capture.status != CaptureStatus::Success || !received.observation.has_value()) {
            session_.capture_status = received.capture.status;
            return;
        }
        dispatch_observation(*received.observation);
    } catch (...) {
        session_.capture_status = CaptureStatus::ReceiveFailed;
    }
}

void LinuxNetworkScanTransport::dispatch_observation(const PacketObservation &observation) noexcept
{
    const auto complete_unreachable = [this, &observation](portscan::PortProbeId id) noexcept {
        const auto pending = pending_.find(id);
        if (pending == pending_.end()) {
            return;
        }
        portscan::PortResponse response;
        response.id = id;
        response.source_address = pending->second.submission.target;
        response.source_ip = pending->second.submission.target_ip;
        response.kind = portscan::PortResponseKind::Unreachable;
        response.received_at = observation.received_at;
        portscan::PortResponseCallback callback = pending->second.callback;
        correlation_.remove(pending->second.correlation_key);
        pending_.erase(pending);
        ++session_.completed;
        callback(response);
    };

    if (observation.valid() && observation.ipv6.has_value() && observation.icmpv6.has_value() &&
        observation.icmpv6->type() == packet::Icmpv6Type::DestinationUnreachable) {
        const std::span<const std::uint8_t> quoted_bytes{observation.icmpv6->payload()};
        const auto quoted_ip = packet::IPv6::parse(quoted_bytes);
        if (quoted_ip.has_value() && quoted_ip->next_header() == kTcpProtocol &&
            quoted_bytes.size() >= quoted_ip->serialized_size()) {
            const auto quoted_tcp = packet::TCP::parse(quoted_bytes.subspan(quoted_ip->serialized_size()));
            if (quoted_tcp.has_value()) {
                const core::IpAddress quoted_source = core::IpAddress::from_ipv6(quoted_ip->source_address());
                const core::IpAddress quoted_destination = core::IpAddress::from_ipv6(quoted_ip->destination_address());
                for (const auto &[id, pending] : pending_) {
                    if (pending.submission.probe != portscan::ScanProbeType::TcpSyn ||
                        pending.submission.source_ip.bytes != quoted_source.bytes ||
                        pending.submission.target_ip.bytes != quoted_destination.bytes ||
                        quoted_tcp->source_port() != pending.submission.source_port ||
                        quoted_tcp->destination_port() != pending.submission.port.number ||
                        quoted_tcp->sequence_number() != pending.submission.sequence_number) {
                        continue;
                    }
                    complete_unreachable(id);
                    return;
                }
            }
        }
    }

    if (observation.valid() && observation.ipv4.has_value() && observation.icmp.has_value() &&
        observation.ipv4->destination_address() == source_ipv4_ &&
        observation.icmp->type() == packet::IcmpType::DestinationUnreachable) {
        const std::span<const std::uint8_t> quoted_bytes{observation.icmp->payload()};
        const auto quoted_ip = packet::IPv4::parse(quoted_bytes);
        if (quoted_ip.has_value() && quoted_ip->protocol() == kTcpProtocol &&
            quoted_bytes.size() >= quoted_ip->serialized_size()) {
            const auto quoted_tcp = packet::TCP::parse(quoted_bytes.subspan(quoted_ip->serialized_size()));
            if (quoted_tcp.has_value()) {
                const core::IpAddress quoted_source = core::IpAddress::from_ipv4(quoted_ip->source_address());
                const core::IpAddress quoted_destination = core::IpAddress::from_ipv4(quoted_ip->destination_address());
                for (const auto &[id, pending] : pending_) {
                    if (pending.submission.probe != portscan::ScanProbeType::TcpSyn ||
                        pending.submission.source_ip.bytes != quoted_source.bytes ||
                        pending.submission.target_ip.bytes != quoted_destination.bytes ||
                        quoted_tcp->source_port() != pending.submission.source_port ||
                        quoted_tcp->destination_port() != pending.submission.port.number ||
                        quoted_tcp->sequence_number() != pending.submission.sequence_number) {
                        continue;
                    }
                    complete_unreachable(id);
                    return;
                }
            }
        }
    }

    if (observation.valid() && observation.ipv6.has_value() && observation.tcp.has_value()) {
        const packet::TCP &tcp = *observation.tcp;
        const core::IpAddress observed_source = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        const core::IpAddress observed_destination = core::IpAddress::from_ipv6(observation.ipv6->destination_address());
        std::optional<portscan::PortProbeId> matched_id;
        for (const auto &[id, pending] : pending_) {
            if (!pending.submission.target_ip.is_ipv6() || pending.submission.source_ip.is_ipv6() == false ||
                pending.submission.target_ip.bytes != observed_source.bytes ||
                pending.submission.source_ip.bytes != observed_destination.bytes ||
                pending.submission.source_port != tcp.destination_port() ||
                pending.submission.port.number != tcp.source_port()) {
                continue;
            }
            const bool ack_matches = tcp.acknowledgment_number() == pending.submission.sequence_number + 1U;
            const bool rst_without_ack = packet::has_flag(tcp.flags(), packet::TcpFlag::Rst) &&
                                         tcp.acknowledgment_number() == 0U;
            if (!ack_matches && !rst_without_ack) {
                continue;
            }
            if (matched_id.has_value()) {
                matched_id.reset();
                break;
            }
            matched_id = id;
        }
        if (matched_id.has_value()) {
            const auto pending = pending_.find(*matched_id);
            if (pending != pending_.end()) {
                std::vector<std::uint8_t> bytes(tcp.serialized_size(), 0U);
                if (tcp.serialize(bytes) == core::StatusCode::Ok) {
                    portscan::PortResponse response;
                    response.id = *matched_id;
                    response.source_ip = observed_source;
                    response.source_ip.scope = pending->second.submission.target_ip.scope;
                    response.source_address = response.source_ip.to_string();
                    response.kind = portscan::PortResponseKind::Packet;
                    response.bytes = std::move(bytes);
                    response.received_at = observation.received_at;
                    portscan::PortResponseCallback callback = pending->second.callback;
                    correlation_.remove(pending->second.correlation_key);
                    pending_.erase(pending);
                    ++session_.completed;
                    callback(response);
                }
            }
        }
        return;
    }
    PacketFilter filter;
    filter.protocol = PacketProtocol::TCP;
    if (!matches(filter, observation) || !observation.ipv4.has_value() || !observation.tcp.has_value() ||
        observation.ipv4->destination_address() != source_ipv4_) {
        return;
    }
    const std::uint32_t source_address = observation.ipv4->source_address();
    const packet::TCP &tcp = *observation.tcp;
    std::optional<portscan::PortProbeId> matched_id;
    if (tcp.acknowledgment_number() != 0U) {
        const CorrelationKey key{
            source_address,
            tcp.destination_port(),
            tcp.source_port(),
            tcp.acknowledgment_number() - 1U};
        const CorrelationResult found = correlation_.lookup(key, std::chrono::steady_clock::now());
        if (found.status == CorrelationStatus::Found && found.entry.has_value()) {
            matched_id = static_cast<portscan::PortProbeId>(found.entry->token);
        }
    } else {
        for (const auto &[id, pending] : pending_) {
            if (pending.correlation_key.target_ipv4 == source_address &&
                pending.submission.source_port == tcp.destination_port() &&
                pending.submission.port.number == tcp.source_port()) {
                if (matched_id.has_value()) {
                    matched_id.reset();
                    break;
                }
                matched_id = id;
            }
        }
    }
    if (!matched_id.has_value()) {
        return;
    }
    const auto pending = pending_.find(*matched_id);
    if (pending == pending_.end()) {
        return;
    }
    std::vector<std::uint8_t> bytes(tcp.serialized_size(), 0U);
    if (tcp.serialize(bytes) != core::StatusCode::Ok) {
        return;
    }
    portscan::PortResponse response;
    response.id = *matched_id;
    response.source_address = ipv4_text(source_address);
    response.source_ip = core::IpAddress::from_ipv4(source_address);
    response.kind = portscan::PortResponseKind::Packet;
    response.bytes = std::move(bytes);
    response.received_at = observation.received_at;
    portscan::PortResponseCallback callback = pending->second.callback;
    correlation_.remove(pending->second.correlation_key);
    pending_.erase(pending);
    ++session_.completed;
    callback(response);
}

std::optional<std::vector<std::uint8_t>> LinuxNetworkScanTransport::compose_frame(
    const portscan::PortSubmission &submission) const
{
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : core::parse_ip_address(submission.target).value_or(core::IpAddress{});
    if (!target_ip.valid() || !submission.source_ip.valid()) {
        return std::nullopt;
    }
    const auto tcp = packet::TCP::parse(std::span<const std::uint8_t>{submission.packet});
    if (!tcp.has_value()) {
        return std::nullopt;
    }
    const auto destination = destination_mac(target_ip);
    if (!destination.has_value()) {
        return std::nullopt;
    }
    packet::Packet packet;
    std::optional<packet::TCP> wire_tcp;
    if (target_ip.is_ipv4() && submission.source_ip.is_ipv4()) {
        const std::uint32_t target_ipv4 = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                          static_cast<std::uint32_t>(target_ip.bytes[3]);
        const std::uint32_t source_ipv4 = (static_cast<std::uint32_t>(submission.source_ip.bytes[0]) << 24U) |
                                          (static_cast<std::uint32_t>(submission.source_ip.bytes[1]) << 16U) |
                                          (static_cast<std::uint32_t>(submission.source_ip.bytes[2]) << 8U) |
                                          static_cast<std::uint32_t>(submission.source_ip.bytes[3]);
        packet::IPv4 ipv4;
        ipv4.set_protocol(kTcpProtocol);
        ipv4.set_source_address(source_ipv4);
        ipv4.set_destination_address(target_ipv4);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, kEtherTypeIpv4));
        packet.set_ipv4(ipv4);
        std::vector<std::uint8_t> tcp_bytes(tcp->serialized_size(), 0U);
        if (tcp->serialize_with_checksum(
                std::span<std::uint8_t>{tcp_bytes}, source_ipv4, target_ipv4,
                std::span<const std::uint8_t>{tcp->payload()}) != core::StatusCode::Ok) {
            return std::nullopt;
        }
        wire_tcp = packet::TCP::parse(std::span<const std::uint8_t>{tcp_bytes});
    } else if (target_ip.is_ipv6() && submission.source_ip.is_ipv6()) {
        packet::IPv6 ipv6;
        ipv6.set_next_header(kTcpProtocol);
        ipv6.set_source_address(submission.source_ip.bytes);
        ipv6.set_destination_address(target_ip.bytes);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, 0x86DDU));
        packet.set_ipv6(ipv6);
        std::vector<std::uint8_t> tcp_bytes(tcp->serialized_size(), 0U);
        if (tcp->serialize_with_checksum(
                std::span<std::uint8_t>{tcp_bytes}, submission.source_ip.bytes, target_ip.bytes,
                std::span<const std::uint8_t>{tcp->payload()}) != core::StatusCode::Ok) {
            return std::nullopt;
        }
        wire_tcp = packet::TCP::parse(std::span<const std::uint8_t>{tcp_bytes});
    } else {
        return std::nullopt;
    }
    if (!wire_tcp.has_value()) {
        return std::nullopt;
    }
    packet.set_tcp(*wire_tcp);
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

std::optional<std::array<std::uint8_t, 6U>> LinuxNetworkScanTransport::destination_mac(
    std::uint32_t target_ipv4) const
{
    if (config_.destination_mac.has_value()) {
        return config_.destination_mac;
    }
    if (config_.interface_name == "lo") {
        return std::array<std::uint8_t, 6U>{};
    }
    return neighbor_mac_for(config_.interface_name, target_ipv4);
}

std::optional<std::array<std::uint8_t, 6U>> LinuxNetworkScanTransport::destination_mac(
    const core::IpAddress &target_ip) const
{
    if (target_ip.is_ipv4()) {
        const std::uint32_t address = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                      static_cast<std::uint32_t>(target_ip.bytes[3]);
        return destination_mac(address);
    }
    if (config_.destination_mac.has_value()) {
        return config_.destination_mac;
    }
    if (config_.interface_name == "lo") {
        return std::array<std::uint8_t, 6U>{};
    }
    return std::nullopt;
}

std::optional<core::IpAddress> LinuxNetworkScanTransport::source_address_for(
    const core::IpAddress &target_ip) const
{
    if (target_ip.is_ipv4()) {
        return source_ipv4_ == 0U ? std::nullopt : std::optional<core::IpAddress>{core::IpAddress::from_ipv4(source_ipv4_)};
    }
    if (!source_ipv6_.has_value()) {
        return std::nullopt;
    }
    core::IpAddress source = *source_ipv6_;
    if (target_ip.is_ipv6_link_local()) {
        if (!core::ipv6_scope_matches_interface(target_ip, config_.interface_name)) {
            return std::nullopt;
        }
        source.scope = target_ip.scope;
    }
    return source;
}

} // namespace skan::net
