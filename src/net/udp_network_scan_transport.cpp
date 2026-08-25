#include "net/udp_network_scan_transport.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <new>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "discovery/discovery_types.hpp"
#include "packet/checksum.hpp"
#include "packet/ipv6.hpp"
#include "packet/ipv6_quote.hpp"
#include "packet/packet.hpp"

namespace skan::net {
namespace {

constexpr std::uint8_t kUdpProtocol = 17U;
constexpr std::uint8_t kIcmpProtocol = 1U;

std::optional<std::uint32_t> parse_ipv4(std::string_view text)
{
    in_addr address{};
    if (::inet_pton(AF_INET, std::string{text}.c_str(), &address) != 1) {
        return std::nullopt;
    }
    return ntohl(address.s_addr);
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
                                            text.data() + static_cast<std::ptrdiff_t>(begin + length), value, 16);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != text.data() + static_cast<std::ptrdiff_t>(begin + length) || value > 255U) {
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
    if (interface_name.size() >= IFNAMSIZ) {
        (void)::close(descriptor);
        return std::nullopt;
    }
    ifreq request{};
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

std::optional<std::array<std::uint8_t, 6U>> neighbor_mac_for(std::string_view interface_name,
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
    return ::inet_ntop(AF_INET, &value, buffer, sizeof(buffer)) == nullptr ? std::string{} : std::string(buffer);
}

} // namespace

LinuxUDPScanTransport::LinuxUDPScanTransport(io::IOEngine &io_engine, NetworkScanConfig config)
    : io_engine_(io_engine), config_(std::move(config)), receiver_(capture_, config_.max_frame_size)
{
}

LinuxUDPScanTransport::~LinuxUDPScanTransport() { close(); }

NetworkScanResult LinuxUDPScanTransport::open()
{
    close();
    if (config_.interface_name.empty() || config_.max_frame_size == 0U) {
        return {NetworkScanStatus::InvalidConfiguration, 0, "explicit interface and positive frame limit are required"};
    }
    const InterfaceResult interface_result = find_interface_result(config_.interface_name);
    if (!interface_result.success()) {
        const NetworkScanStatus status = interface_result.status == InterfaceStatus::PermissionDenied
                                             ? NetworkScanStatus::PermissionDenied
                                             : interface_result.status == InterfaceStatus::NotSupported
                                                   ? NetworkScanStatus::NotSupported
                                                   : interface_result.status == InterfaceStatus::InterfaceNotFound
                                                         ? NetworkScanStatus::InterfaceNotFound
                                                         : NetworkScanStatus::SystemError;
        return {status, interface_result.system_error, interface_result.message};
    }
    if (interface_result.interface.ipv4_addresses.empty() && interface_result.interface.ipv6_addresses.empty()) {
        return {NetworkScanStatus::NotSupported, 0, "selected interface has no IPv4 or IPv6 address"};
    }
    const auto mac = local_mac_for(config_.interface_name);
    if (!mac.has_value()) {
        return {NetworkScanStatus::NotSupported, errno, "local interface MAC address is unavailable"};
    }
    local_mac_ = *mac;
    source_ipv4_ = 0U;
    if (!interface_result.interface.ipv4_addresses.empty()) {
        const auto &address = interface_result.interface.ipv4_addresses.front().ipv4;
        source_ipv4_ = (static_cast<std::uint32_t>(address[0]) << 24U) |
                       (static_cast<std::uint32_t>(address[1]) << 16U) |
                       (static_cast<std::uint32_t>(address[2]) << 8U) | static_cast<std::uint32_t>(address[3]);
    }
    source_ipv6_.reset();
    if (!interface_result.interface.ipv6_addresses.empty()) {
        source_ipv6_ = interface_result.interface.ipv6_addresses.front().address;
    }

    const CaptureResult capture_result = receiver_.open(
        CaptureConfig{config_.interface_name, config_.max_frame_size, config_.nonblocking});
    if (!capture_result.success()) {
        const NetworkScanStatus status = capture_result.status == CaptureStatus::PermissionDenied
                                             ? NetworkScanStatus::PermissionDenied
                                             : capture_result.status == CaptureStatus::InterfaceNotFound
                                                   ? NetworkScanStatus::InterfaceNotFound
                                                   : capture_result.status == CaptureStatus::NotSupported
                                                         ? NetworkScanStatus::NotSupported
                                                         : NetworkScanStatus::SystemError;
        return {status, capture_result.system_error, capture_result.message};
    }
    const TransportResult transport_result = transport_.open(
        TransportConfig{config_.interface_name, config_.nonblocking});
    if (!transport_result.success()) {
        receiver_.close();
        const NetworkScanStatus status = transport_result.status == TransportStatus::PermissionDenied
                                             ? NetworkScanStatus::PermissionDenied
                                             : transport_result.status == TransportStatus::NotSupported
                                                   ? NetworkScanStatus::NotSupported
                                                   : NetworkScanStatus::SystemError;
        return {status, transport_result.system_error, transport_result.message};
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
    return {NetworkScanStatus::Success, 0, {}};
}

void LinuxUDPScanTransport::close() noexcept
{
    pending_.clear();
    receiver_.close();
    transport_.close();
    session_.active = false;
    session_.transport_status = TransportStatus::Closed;
    session_.capture_status = CaptureStatus::Closed;
}

bool LinuxUDPScanTransport::is_open() const noexcept
{
    return session_.active && transport_.is_open() && receiver_.is_open();
}

bool LinuxUDPScanTransport::supports() const noexcept { return is_open(); }

core::StatusCode LinuxUDPScanTransport::submit(const portscan::UDPSubmission &submission,
                                               portscan::UDPResponseCallback callback)
{
    if (!is_open()) {
        return core::StatusCode::PermissionDenied;
    }
    if (submission.id == 0U || submission.port.protocol != portscan::Protocol::Udp ||
        submission.port.number == 0U || submission.target.empty() || !callback || pending_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    const auto parsed_target = core::parse_ip_address(submission.target);
    const core::IpAddress target_ip = submission.destination_ip.valid()
                                          ? submission.destination_ip
                                          : parsed_target.value_or(core::IpAddress{});
    if (!target_ip.valid() || submission.source_port == 0U) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    portscan::UDPSubmission effective = submission;
    effective.destination_ip = target_ip;
    const auto selected_source = source_address_for(target_ip);
    if (!selected_source.has_value()) {
        ++session_.failed;
        return core::StatusCode::PermissionDenied;
    }
    effective.source_ip = *selected_source;
    if (target_ip.is_ipv4()) {
        effective.destination_ipv4 = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                    (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                    (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                    static_cast<std::uint32_t>(target_ip.bytes[3]);
    }
    const auto frame = compose_frame(effective);
    if (!frame.has_value()) {
        ++session_.failed;
        return core::StatusCode::PermissionDenied;
    }
    try {
        pending_.emplace(effective.id, Pending{effective, std::move(callback)});
    } catch (const std::bad_alloc &) {
        ++session_.failed;
        return core::StatusCode::MemoryError;
    }
    const TransportResult send_result = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!send_result.success()) {
        pending_.erase(submission.id);
        ++session_.failed;
        session_.transport_status = send_result.status;
        return send_result.status == TransportStatus::PermissionDenied ? core::StatusCode::PermissionDenied
                                                                        : core::StatusCode::IoError;
    }
    ++session_.submitted;
    return core::StatusCode::Ok;
}

core::StatusCode LinuxUDPScanTransport::cancel(portscan::UDPProbeId id) noexcept
{
    const auto found = pending_.find(id);
    if (found != pending_.end()) {
        pending_.erase(found);
        ++session_.timed_out;
    }
    return core::StatusCode::Ok;
}

const ScanSession &LinuxUDPScanTransport::session() const noexcept { return session_; }
int LinuxUDPScanTransport::transport_file_descriptor() const noexcept { return transport_.file_descriptor(); }
int LinuxUDPScanTransport::capture_file_descriptor() const noexcept { return capture_.file_descriptor(); }

void LinuxUDPScanTransport::on_capture_event(io::Event &event) noexcept
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

std::optional<portscan::UDPProbeId> LinuxUDPScanTransport::match_udp(
    const PacketObservation &observation) const noexcept
{
    if (!observation.valid() || !observation.udp.has_value()) {
        return std::nullopt;
    }
    std::optional<portscan::UDPProbeId> matched;
    for (const auto &[id, pending] : pending_) {
        bool addresses_match = false;
        if (observation.ipv4.has_value()) {
            const auto target = parse_ipv4(pending.submission.target);
            addresses_match = target.has_value() && observation.ipv4->source_address() == *target &&
                              observation.ipv4->destination_address() == source_ipv4_;
        } else if (observation.ipv6.has_value()) {
            addresses_match = pending.submission.source_ip.valid() && pending.submission.source_ip.is_ipv6() &&
                              pending.submission.destination_ip.valid() && pending.submission.destination_ip.is_ipv6() &&
                              observation.ipv6->source_address() == pending.submission.destination_ip.bytes &&
                              observation.ipv6->destination_address() == pending.submission.source_ip.bytes;
        }
        if (!addresses_match || observation.udp->source_port() != pending.submission.port.number ||
            observation.udp->destination_port() != pending.submission.source_port) {
            continue;
        }
        if (matched.has_value()) {
            return std::nullopt;
        }
        matched = id;
    }
    return matched;
}

std::optional<portscan::UDPProbeId> LinuxUDPScanTransport::match_icmp(
    const PacketObservation &observation) const noexcept
{
    if (!observation.valid() || !observation.ipv4.has_value() || !observation.icmp.has_value() ||
        observation.icmp->type() != packet::IcmpType::DestinationUnreachable ||
        observation.ipv4->destination_address() != source_ipv4_) {
        return std::nullopt;
    }
    const std::span<const std::uint8_t> embedded_bytes{observation.icmp->payload()};
    if (embedded_bytes.size() < packet::IPv4::kMinimumHeaderSize + packet::UDP::kHeaderSize) {
        return std::nullopt;
    }
    const std::uint8_t ihl = static_cast<std::uint8_t>(embedded_bytes[0] & 0x0FU);
    const std::size_t header_size = static_cast<std::size_t>(ihl) * 4U;
    if ((embedded_bytes[0] >> 4U) != 4U || ihl < 5U || embedded_bytes.size() < header_size + packet::UDP::kHeaderSize ||
        packet::checksum::internet(embedded_bytes.first(header_size)) != 0U) {
        return std::nullopt;
    }
    const std::uint16_t total_length = packet::wire::read_u16(embedded_bytes, 2U);
    if (total_length < header_size + packet::UDP::kHeaderSize) {
        return std::nullopt;
    }
    if (packet::wire::read_u16(embedded_bytes, header_size + 4U) < packet::UDP::kHeaderSize) {
        return std::nullopt;
    }
    const std::uint32_t embedded_source = packet::wire::read_u32(embedded_bytes, 12U);
    const std::uint32_t embedded_destination = packet::wire::read_u32(embedded_bytes, 16U);
    if (embedded_bytes[9] != kUdpProtocol) {
        return std::nullopt;
    }
    const std::size_t udp_offset = header_size;
    const std::uint16_t embedded_source_port = packet::wire::read_u16(embedded_bytes, udp_offset);
    const std::uint16_t embedded_destination_port = packet::wire::read_u16(embedded_bytes, udp_offset + 2U);
    std::optional<portscan::UDPProbeId> matched;
    for (const auto &[id, pending] : pending_) {
        const auto target = parse_ipv4(pending.submission.target);
        if (!target.has_value() || embedded_source != source_ipv4_ || embedded_destination != *target ||
            embedded_source_port != pending.submission.source_port ||
            embedded_destination_port != pending.submission.port.number ||
            observation.ipv4->source_address() != *target) {
            continue;
        }
        if (matched.has_value()) {
            return std::nullopt;
        }
        matched = id;
    }
    return matched;
}

std::optional<portscan::UDPProbeId> LinuxUDPScanTransport::match_icmpv6(
    const PacketObservation &observation) const noexcept
{
    if (!observation.valid() || !observation.ipv6.has_value() || !observation.icmpv6.has_value() ||
        observation.icmpv6->type() != packet::Icmpv6Type::DestinationUnreachable ||
        observation.icmpv6->code() > 4U) {
        return std::nullopt;
    }
    const auto quote = packet::parse_ipv6_udp_quote(
        std::span<const std::uint8_t>{observation.icmpv6->payload()});
    if (!quote.has_value()) {
        return std::nullopt;
    }
    std::optional<portscan::UDPProbeId> matched;
    for (const auto &[id, pending] : pending_) {
        if (!pending.submission.source_ip.valid() || !pending.submission.destination_ip.valid() ||
            !pending.submission.source_ip.is_ipv6() || !pending.submission.destination_ip.is_ipv6() ||
            quote->ip.source_address() != pending.submission.source_ip.bytes ||
            quote->ip.destination_address() != pending.submission.destination_ip.bytes ||
            observation.ipv6->destination_address() != pending.submission.source_ip.bytes ||
            quote->source_port != pending.submission.source_port ||
            quote->destination_port != pending.submission.port.number ||
            observation.ipv6->source_address() != pending.submission.destination_ip.bytes) {
            continue;
        }
        if (matched.has_value()) {
            return std::nullopt;
        }
        matched = id;
    }
    return matched;
}

void LinuxUDPScanTransport::dispatch_observation(const PacketObservation &observation) noexcept
{
    std::optional<portscan::UDPProbeId> id = match_udp(observation);
    portscan::UDPResponseKind kind = portscan::UDPResponseKind::Datagram;
    if (!id.has_value()) {
        if (observation.icmpv6.has_value()) {
            id = match_icmpv6(observation);
            if (!id.has_value()) {
                return;
            }
            const std::uint8_t code = observation.icmpv6->code();
            if (code == 4U) {
                kind = portscan::UDPResponseKind::IcmpPortUnreachable;
            } else if (code == 1U) {
                kind = portscan::UDPResponseKind::IcmpAdministrativelyProhibited;
            } else if (code == 0U || code == 2U || code == 3U) {
                kind = portscan::UDPResponseKind::IcmpNetworkUnreachable;
            } else {
                kind = portscan::UDPResponseKind::Malformed;
            }
        } else {
            id = match_icmp(observation);
            if (!id.has_value()) {
                return;
            }
            const std::uint8_t code = observation.icmp->code();
            if (code == 3U) {
                kind = portscan::UDPResponseKind::IcmpPortUnreachable;
            } else if (code == 9U || code == 10U || code == 13U) {
                kind = portscan::UDPResponseKind::IcmpAdministrativelyProhibited;
            } else if (code == 0U || code == 1U) {
                kind = portscan::UDPResponseKind::IcmpNetworkUnreachable;
            } else {
                kind = portscan::UDPResponseKind::Malformed;
            }
        }
    }
    const auto found = pending_.find(*id);
    if (found == pending_.end()) {
        return;
    }
    portscan::UDPResponse response;
    response.id = *id;
    if (observation.ipv4.has_value()) {
        response.source_address = ipv4_text(observation.ipv4->source_address());
        response.source_ipv4 = observation.ipv4->source_address();
        response.source_ip = core::IpAddress::from_ipv4(observation.ipv4->source_address());
    } else if (observation.ipv6.has_value()) {
        response.source_ip = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        response.source_address = response.source_ip.to_string();
    }
    response.kind = kind;
    response.received_at = observation.received_at;
    if (observation.udp.has_value()) {
        response.source_port = observation.udp->source_port();
        response.destination_port = observation.udp->destination_port();
        response.bytes.resize(observation.udp->serialized_size());
        if (observation.udp->serialize(response.bytes) != core::StatusCode::Ok) {
            return;
        }
    }
    portscan::UDPResponseCallback callback = found->second.callback;
    pending_.erase(found);
    ++session_.completed;
    callback(response);
}

std::optional<std::vector<std::uint8_t>> LinuxUDPScanTransport::compose_frame(
    const portscan::UDPSubmission &submission) const
{
    const core::IpAddress target_ip = submission.destination_ip.valid()
                                          ? submission.destination_ip
                                          : core::parse_ip_address(submission.target).value_or(core::IpAddress{});
    if (!target_ip.valid() || !submission.source_ip.valid()) {
        return std::nullopt;
    }
    const auto udp = packet::UDP::parse(std::span<const std::uint8_t>{submission.packet});
    const auto destination = destination_mac(target_ip);
    if (!udp.has_value() || !destination.has_value()) {
        return std::nullopt;
    }
    packet::Packet packet;
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
        ipv4.set_protocol(kUdpProtocol);
        ipv4.set_source_address(source_ipv4);
        ipv4.set_destination_address(target_ipv4);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, 0x0800U));
        packet.set_ipv4(ipv4);
    } else if (target_ip.is_ipv6() && submission.source_ip.is_ipv6()) {
        packet::IPv6 ipv6;
        ipv6.set_next_header(kUdpProtocol);
        ipv6.set_source_address(submission.source_ip.bytes);
        ipv6.set_destination_address(target_ip.bytes);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, 0x86DDU));
        packet.set_ipv6(ipv6);
    } else {
        return std::nullopt;
    }
    packet.set_udp(*udp);
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

std::optional<std::array<std::uint8_t, 6U>> LinuxUDPScanTransport::destination_mac(
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

std::optional<std::array<std::uint8_t, 6U>> LinuxUDPScanTransport::destination_mac(
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

std::optional<core::IpAddress> LinuxUDPScanTransport::source_address_for(
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
