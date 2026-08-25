#include "net/linux_os_probe_transport.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <net/if.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#include "discovery/discovery_types.hpp"
#include "packet/checksum.hpp"
#include "packet/packet.hpp"

namespace skan::net {
namespace {

constexpr std::uint8_t kTcpProtocol = 6U;
constexpr std::uint8_t kUdpProtocol = 17U;
constexpr std::uint8_t kIcmpProtocol = 1U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;

std::optional<std::uint32_t> parse_ipv4(std::string_view text)
{
    in_addr address{};
    if (::inet_pton(AF_INET, std::string{text}.c_str(), &address) != 1) {
        return std::nullopt;
    }
    return ntohl(address.s_addr);
}

std::string ipv4_text(std::uint32_t address)
{
    in_addr value{};
    value.s_addr = htonl(address);
    char buffer[INET_ADDRSTRLEN]{};
    return ::inet_ntop(AF_INET, &value, buffer, sizeof(buffer)) == nullptr ? std::string{} : std::string{buffer};
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
        const auto parsed = parse_ipv4(address);
        if (!parsed.has_value() || *parsed != target_ipv4) {
            continue;
        }
        return parse_mac(hardware_address);
    }
    return std::nullopt;
}

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

core::StatusCode map_network_status(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return core::StatusCode::Ok;
    case NetworkScanStatus::InvalidConfiguration:
        return core::StatusCode::InvalidArgument;
    case NetworkScanStatus::InterfaceNotFound:
        return core::StatusCode::NotFound;
    case NetworkScanStatus::PermissionDenied:
    case NetworkScanStatus::NotSupported:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::NotOpen:
    case NetworkScanStatus::SystemError:
        return core::StatusCode::IoError;
    }
    return core::StatusCode::IoError;
}

bool is_tcp_probe(osdetect::OSProbeType type) noexcept
{
    return type != osdetect::OSProbeType::IcmpEcho && type != osdetect::OSProbeType::UdpFingerprint &&
           type != osdetect::OSProbeType::UdpPortUnreachable;
}

} // namespace

std::size_t LinuxOSProbeTransport::CorrelationHash::operator()(const Correlation &value) const noexcept
{
    std::size_t hash = static_cast<std::size_t>(value.target_ipv4);
    hash = (hash * 131U) ^ value.source_port;
    hash = (hash * 131U) ^ value.destination_port;
    hash = (hash * 131U) ^ value.sequence;
    hash = (hash * 131U) ^ value.identity;
    hash = (hash * 131U) ^ value.protocol;
    return hash;
}

LinuxOSProbeTransport::LinuxOSProbeTransport(io::IOEngine &engine, NetworkScanConfig config)
    : engine_(engine), config_(std::move(config)), receiver_(capture_, config_.max_frame_size)
{
}

LinuxOSProbeTransport::~LinuxOSProbeTransport()
{
    close();
}

NetworkScanResult LinuxOSProbeTransport::open()
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
    if (interface_result.interface.ipv4_addresses.empty()) {
        return {NetworkScanStatus::NotSupported, 0, "selected interface has no IPv4 address"};
    }
    const auto mac = local_mac_for(config_.interface_name);
    if (!mac.has_value()) {
        return {NetworkScanStatus::NotSupported, errno, "local interface MAC address is unavailable"};
    }
    std::copy(mac->begin(), mac->end(), local_mac_.begin());
    const auto &address = interface_result.interface.ipv4_addresses.front().ipv4;
    source_ipv4_ = (static_cast<std::uint32_t>(address[0]) << 24U) |
                   (static_cast<std::uint32_t>(address[1]) << 16U) |
                   (static_cast<std::uint32_t>(address[2]) << 8U) | static_cast<std::uint32_t>(address[3]);

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
        return {map_transport_status(transport_result.status), transport_result.system_error, transport_result.message};
    }
    const core::StatusCode attach_status = receiver_.attach(
        engine_, [this](io::Event &event) { on_capture_event(event); });
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

void LinuxOSProbeTransport::close() noexcept
{
    pending_.clear();
    correlations_.clear();
    receiver_.close();
    transport_.close();
    session_.active = false;
    session_.transport_status = TransportStatus::Closed;
    session_.capture_status = CaptureStatus::Closed;
}

bool LinuxOSProbeTransport::is_open() const noexcept
{
    return session_.active && transport_.is_open() && receiver_.is_open();
}

bool LinuxOSProbeTransport::supports(osdetect::OSProbeType type) const noexcept
{
    return is_open() && (is_tcp_probe(type) || type == osdetect::OSProbeType::IcmpEcho ||
                         type == osdetect::OSProbeType::UdpFingerprint || type == osdetect::OSProbeType::UdpPortUnreachable);
}

std::string LinuxOSProbeTransport::local_source_address() const
{
    return source_ipv4_ == 0U ? std::string{} : ipv4_text(source_ipv4_);
}

core::StatusCode LinuxOSProbeTransport::submit(osdetect::OSProbeSubmission submission, osdetect::OSProbeCallback callback)
{
    if (!is_open()) {
        return core::StatusCode::PermissionDenied;
    }
    if (submission.id == 0U || !callback || submission.target.empty() || pending_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    const auto target = parse_ipv4(submission.target);
    if (!target.has_value()) {
        ++session_.failed;
        return core::StatusCode::InvalidArgument;
    }
    const auto frame = compose_frame(submission);
    if (!frame.has_value()) {
        ++session_.failed;
        return core::StatusCode::PermissionDenied;
    }
    Correlation correlation;
    correlation.target_ipv4 = *target;
    correlation.protocol = submission.type == osdetect::OSProbeType::IcmpEcho
                               ? kIcmpProtocol
                               : (submission.type == osdetect::OSProbeType::UdpFingerprint ||
                                          submission.type == osdetect::OSProbeType::UdpPortUnreachable
                                      ? kUdpProtocol
                                      : kTcpProtocol);
    correlation.source_port = correlation.protocol == kIcmpProtocol ? 0U : submission.destination_port;
    correlation.destination_port = correlation.protocol == kIcmpProtocol ? 0U : submission.source_port;
    correlation.sequence = submission.sequence_number;
    correlation.identity = submission.type == osdetect::OSProbeType::IcmpEcho
                               ? (static_cast<std::uint32_t>(submission.correlation_identifier) << 16U) |
                                     submission.correlation_sequence
                               : 0U;
    if (correlations_.contains(correlation)) {
        return core::StatusCode::InvalidArgument;
    }
    const osdetect::OSProbeId submission_id = submission.id;
    try {
        pending_.emplace(submission_id, Pending{std::move(submission), std::move(callback)});
        correlations_.emplace(correlation, submission_id);
    } catch (const std::bad_alloc &) {
        pending_.erase(submission_id);
        correlations_.erase(correlation);
        return core::StatusCode::MemoryError;
    }
    const TransportResult send_result = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!send_result.success()) {
        correlations_.erase(correlation);
        pending_.erase(submission_id);
        ++session_.failed;
        session_.transport_status = send_result.status;
        return map_network_status(map_transport_status(send_result.status));
    }
    ++session_.submitted;
    return core::StatusCode::Ok;
}

core::StatusCode LinuxOSProbeTransport::cancel(osdetect::OSProbeId id) noexcept
{
    const auto found = pending_.find(id);
    if (found == pending_.end()) {
        return core::StatusCode::Ok;
    }
    for (auto iterator = correlations_.begin(); iterator != correlations_.end();) {
        if (iterator->second == id) {
            iterator = correlations_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    pending_.erase(found);
    ++session_.timed_out;
    return core::StatusCode::Ok;
}

const ScanSession &LinuxOSProbeTransport::session() const noexcept { return session_; }
int LinuxOSProbeTransport::transport_file_descriptor() const noexcept { return transport_.file_descriptor(); }
int LinuxOSProbeTransport::capture_file_descriptor() const noexcept { return capture_.file_descriptor(); }

void LinuxOSProbeTransport::on_capture_event(io::Event &event) noexcept
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

std::optional<osdetect::OSProbeId> LinuxOSProbeTransport::match_tcp(const PacketObservation &observation) const noexcept
{
    if (!observation.ipv4.has_value() || !observation.tcp.has_value() ||
        observation.ipv4->destination_address() != source_ipv4_) {
        return std::nullopt;
    }
    const packet::TCP &tcp = *observation.tcp;
    const std::uint32_t target = observation.ipv4->source_address();
    if (tcp.acknowledgment_number() != 0U) {
        const Correlation key{target, tcp.source_port(), tcp.destination_port(),
                              tcp.acknowledgment_number() - 1U, 0U, kTcpProtocol};
        const auto found = correlations_.find(key);
        if (found != correlations_.end()) {
            return found->second;
        }
    }
    std::optional<osdetect::OSProbeId> result;
    for (const auto &[id, pending] : pending_) {
        const auto pending_target = parse_ipv4(pending.submission.target);
        if (!pending_target.has_value() || *pending_target != target ||
            pending.submission.source_port != tcp.destination_port() ||
            pending.submission.destination_port != tcp.source_port()) {
            continue;
        }
        if (result.has_value()) {
            return std::nullopt;
        }
        result = id;
    }
    return result;
}

std::optional<osdetect::OSProbeId> LinuxOSProbeTransport::match_udp(const PacketObservation &observation) const noexcept
{
    if (!observation.ipv4.has_value() || !observation.udp.has_value() ||
        observation.ipv4->destination_address() != source_ipv4_) {
        return std::nullopt;
    }
    const packet::UDP &udp = *observation.udp;
    const Correlation key{observation.ipv4->source_address(), udp.source_port(), udp.destination_port(),
                          0U, 0U, kUdpProtocol};
    const auto found = correlations_.find(key);
    return found == correlations_.end() ? std::nullopt : std::optional<osdetect::OSProbeId>{found->second};
}

std::optional<osdetect::OSProbeId> LinuxOSProbeTransport::match_icmp(const PacketObservation &observation) const noexcept
{
    if (!observation.ipv4.has_value() || !observation.icmp.has_value() ||
        observation.ipv4->destination_address() != source_ipv4_) {
        return std::nullopt;
    }
    const packet::ICMP &icmp = *observation.icmp;
    const std::uint32_t target = observation.ipv4->source_address();
    if (icmp.type() == packet::IcmpType::EchoReply) {
        const Correlation key{target, 0U, 0U, 0U,
                              (static_cast<std::uint32_t>(icmp.identifier()) << 16U) | icmp.sequence(), kIcmpProtocol};
        const auto found = correlations_.find(key);
        return found == correlations_.end() ? std::nullopt : std::optional<osdetect::OSProbeId>{found->second};
    }
    if (icmp.type() != packet::IcmpType::DestinationUnreachable ||
        icmp.payload().size() < packet::IPv4::kMinimumHeaderSize + packet::UDP::kHeaderSize) {
        return std::nullopt;
    }
    const std::span<const std::uint8_t> quoted{icmp.payload()};
    const std::uint8_t ihl = static_cast<std::uint8_t>(quoted[0] & 0x0FU);
    const std::size_t header_size = static_cast<std::size_t>(ihl) * 4U;
    if ((quoted[0] >> 4U) != 4U || ihl < 5U || quoted.size() < header_size + packet::UDP::kHeaderSize ||
        packet::checksum::internet(quoted.first(header_size)) != 0U || quoted[9] != kUdpProtocol ||
        packet::wire::read_u16(quoted, header_size + 4U) < packet::UDP::kHeaderSize ||
        packet::wire::read_u32(quoted, 12U) != source_ipv4_ || packet::wire::read_u32(quoted, 16U) != target) {
        return std::nullopt;
    }
    const Correlation key{target, packet::wire::read_u16(quoted, header_size + 2U),
                          packet::wire::read_u16(quoted, header_size), 0U, 0U, kUdpProtocol};
    const auto found = correlations_.find(key);
    return found == correlations_.end() ? std::nullopt : std::optional<osdetect::OSProbeId>{found->second};
}

void LinuxOSProbeTransport::dispatch_observation(const PacketObservation &observation) noexcept
{
    std::optional<osdetect::OSProbeId> matched;
    if (observation.tcp.has_value()) {
        matched = match_tcp(observation);
    } else if (observation.udp.has_value()) {
        matched = match_udp(observation);
    } else if (observation.icmp.has_value()) {
        matched = match_icmp(observation);
    }
    if (!matched.has_value()) {
        return;
    }
    const auto pending = pending_.find(*matched);
    if (pending == pending_.end()) {
        return;
    }
    osdetect::OSProbeResponse response;
    response.id = *matched;
    response.source_address = observation.ipv4.has_value() ? ipv4_text(observation.ipv4->source_address()) : std::string{};
    response.destination_address = observation.ipv4.has_value() ? ipv4_text(observation.ipv4->destination_address()) : std::string{};
    response.ip_ttl = observation.ipv4.has_value() ? observation.ipv4->ttl() : 0U;
    response.ip_identification = observation.ipv4.has_value() ? observation.ipv4->identification() : 0U;
    response.ip_dont_fragment = observation.ipv4.has_value() &&
                                ((observation.ipv4->flags_fragment_offset() & 0x4000U) != 0U);
    response.received_at = observation.received_at;
    if (observation.tcp.has_value() && observation.ipv4.has_value()) {
        packet::Packet packet;
        packet.set_ipv4(*observation.ipv4);
        packet.set_tcp(*observation.tcp);
        response.bytes = packet.serialize();
        response.kind = packet::has_flag(observation.tcp->flags(), packet::TcpFlag::Rst)
                            ? osdetect::OSProbeResponseKind::Closed
                            : osdetect::OSProbeResponseKind::Data;
        response.source_port = observation.tcp->source_port();
        response.destination_port = observation.tcp->destination_port();
    } else if (observation.udp.has_value()) {
        response.bytes = observation.udp->serialize();
        response.kind = osdetect::OSProbeResponseKind::Data;
        response.source_port = observation.udp->source_port();
        response.destination_port = observation.udp->destination_port();
    } else if (observation.icmp.has_value()) {
        response.bytes = observation.icmp->serialize();
        response.kind = observation.icmp->type() == packet::IcmpType::DestinationUnreachable
                            ? osdetect::OSProbeResponseKind::IcmpError
                            : osdetect::OSProbeResponseKind::Data;
    } else {
        return;
    }
    osdetect::OSProbeCallback callback = pending->second.callback;
    for (auto iterator = correlations_.begin(); iterator != correlations_.end();) {
        if (iterator->second == *matched) {
            iterator = correlations_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    pending_.erase(pending);
    ++session_.completed;
    callback(response);
}

std::optional<std::vector<std::uint8_t>> LinuxOSProbeTransport::compose_frame(
    const osdetect::OSProbeSubmission &submission) const
{
    const auto target = parse_ipv4(submission.target);
    if (!target.has_value() || source_ipv4_ == 0U) {
        return std::nullopt;
    }
    const auto destination = destination_mac(*target);
    if (!destination.has_value()) {
        return std::nullopt;
    }
    packet::IPv4 ipv4;
    ipv4.set_source_address(source_ipv4_);
    ipv4.set_destination_address(*target);
    packet::Packet packet;
    packet.set_ethernet(packet::Ethernet(*destination, local_mac_, kEtherTypeIpv4));
    if (submission.type == osdetect::OSProbeType::IcmpEcho) {
        const auto icmp = packet::ICMP::parse(submission.bytes);
        if (!icmp.has_value()) {
            return std::nullopt;
        }
        ipv4.set_protocol(kIcmpProtocol);
        packet.set_ipv4(ipv4);
        packet.set_icmp(*icmp);
    } else if (submission.type == osdetect::OSProbeType::UdpFingerprint ||
               submission.type == osdetect::OSProbeType::UdpPortUnreachable) {
        const auto udp = packet::UDP::parse(submission.bytes);
        if (!udp.has_value()) {
            return std::nullopt;
        }
        ipv4.set_protocol(kUdpProtocol);
        packet.set_ipv4(ipv4);
        packet.set_udp(*udp);
    } else {
        const auto source_ip = packet::IPv4::parse(submission.bytes);
        if (!source_ip.has_value() || source_ip->protocol() != kTcpProtocol) {
            return std::nullopt;
        }
        const std::size_t header_size = static_cast<std::size_t>(source_ip->ihl()) * 4U;
        const auto tcp = packet::TCP::parse(std::span<const std::uint8_t>{submission.bytes}.subspan(header_size));
        if (!tcp.has_value()) {
            return std::nullopt;
        }
        ipv4.set_protocol(kTcpProtocol);
        ipv4.set_ttl(source_ip->ttl());
        ipv4.set_flags_fragment_offset(source_ip->flags_fragment_offset());
        packet.set_ipv4(ipv4);
        packet.set_tcp(*tcp);
    }
    const std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{frame};
}

std::optional<std::array<std::uint8_t, 6U>> LinuxOSProbeTransport::destination_mac(
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

} // namespace skan::net
