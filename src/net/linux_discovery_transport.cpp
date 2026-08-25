#include "net/linux_discovery_transport.hpp"

#include <arpa/inet.h>
#include <charconv>
#include <cstring>
#include <fstream>
#include <net/if.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "discovery/arp_discovery.hpp"
#include "discovery/discovery_types.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
#include "packet/packet.hpp"
#include "packet/tcp.hpp"

namespace skan::net {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeArp = 0x0806U;
constexpr std::uint8_t kIpProtocolIcmp = 1U;
constexpr std::uint8_t kIpProtocolTcp = 6U;

std::optional<std::array<std::uint8_t, 6U>> parse_mac(std::string_view text)
{
    std::array<std::uint8_t, 6U> result{};
    std::size_t begin = 0U;
    for (std::size_t index = 0U; index < result.size(); ++index) {
        const std::size_t end = text.find(':', begin);
        const std::size_t length = end == std::string_view::npos ? text.size() - begin : end - begin;
        if (length == 0U || length > 2U) {
            return std::nullopt;
        }
        unsigned int value = 0U;
        const char *first = text.data() + static_cast<std::ptrdiff_t>(begin);
        const char *last = first + static_cast<std::ptrdiff_t>(length);
        const auto parsed = std::from_chars(first, last, value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != last || value > 255U) {
            return std::nullopt;
        }
        result[index] = static_cast<std::uint8_t>(value);
        if (index + 1U < result.size()) {
            if (end == std::string_view::npos) {
                return std::nullopt;
            }
            begin = end + 1U;
        } else if (end != std::string_view::npos) {
            return std::nullopt;
        }
    }
    return result;
}

std::optional<std::array<std::uint8_t, 6U>> local_mac_for(std::string_view interface_name)
{
    const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0 || interface_name.size() >= IFNAMSIZ) {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
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
        in_addr parsed{};
        if (::inet_pton(AF_INET, address.c_str(), &parsed) != 1 || ntohl(parsed.s_addr) != target_ipv4) {
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
    return ::inet_ntop(AF_INET, &value, buffer, sizeof(buffer)) == nullptr ? std::string{} : std::string{buffer};
}

std::uint32_t interface_ipv4(const NetworkInterface &interface) noexcept
{
    if (interface.ipv4_addresses.empty()) {
        return 0U;
    }
    const InterfaceAddress &address = interface.ipv4_addresses.front();
    return (static_cast<std::uint32_t>(address.ipv4[0]) << 24U) |
           (static_cast<std::uint32_t>(address.ipv4[1]) << 16U) |
           (static_cast<std::uint32_t>(address.ipv4[2]) << 8U) |
           static_cast<std::uint32_t>(address.ipv4[3]);
}

} // namespace

LinuxDiscoveryTransport::LinuxDiscoveryTransport(io::IOEngine &io_engine, std::string interface_name)
    : io_engine_(io_engine),
      interface_name_(std::move(interface_name)),
      receiver_(capture_)
{
}

LinuxDiscoveryTransport::~LinuxDiscoveryTransport()
{
    close();
}

NetworkScanResult LinuxDiscoveryTransport::open()
{
    close();
    if (interface_name_.empty()) {
        return {NetworkScanStatus::InvalidConfiguration, 0, "an explicit interface is required"};
    }
    const InterfaceResult found = find_interface_result(interface_name_);
    if (!found.success()) {
        return {found.status == InterfaceStatus::InterfaceNotFound
                    ? NetworkScanStatus::InterfaceNotFound
                    : found.status == InterfaceStatus::PermissionDenied
                          ? NetworkScanStatus::PermissionDenied
                          : NetworkScanStatus::SystemError,
                found.system_error,
                found.message};
    }
    const auto mac = local_mac_for(interface_name_);
    if (!mac.has_value()) {
        return {NetworkScanStatus::NotSupported, errno, "selected interface MAC address is unavailable"};
    }
    local_mac_ = *mac;
    source_ipv4_ = interface_ipv4(found.interface);
    if (source_ipv4_ == 0U) {
        return {NetworkScanStatus::NotSupported, 0, "selected interface has no IPv4 address"};
    }
    const CaptureResult capture_result = receiver_.open(CaptureConfig{interface_name_, 65535U, true});
    if (!capture_result.success()) {
        return {capture_result.status == CaptureStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : capture_result.status == CaptureStatus::InterfaceNotFound
                          ? NetworkScanStatus::InterfaceNotFound
                          : NetworkScanStatus::SystemError,
                capture_result.system_error,
                capture_result.message};
    }
    const TransportResult transport_result = transport_.open(TransportConfig{interface_name_, true});
    if (!transport_result.success()) {
        receiver_.close();
        return {transport_result.status == TransportStatus::PermissionDenied
                    ? NetworkScanStatus::PermissionDenied
                    : transport_result.status == TransportStatus::InterfaceNotFound
                          ? NetworkScanStatus::InterfaceNotFound
                          : NetworkScanStatus::SystemError,
                transport_result.system_error,
                transport_result.message};
    }
    const core::StatusCode attach_status = receiver_.attach(
        io_engine_, [this](io::Event &event) { on_capture_event(event); });
    if (attach_status != core::StatusCode::Ok) {
        transport_.close();
        receiver_.close();
        return {NetworkScanStatus::SystemError, 0, "capture descriptor registration failed"};
    }
    open_ = true;
    return {NetworkScanStatus::Success, 0, {}};
}

void LinuxDiscoveryTransport::close() noexcept
{
    pending_.clear();
    response_handler_ = {};
    receiver_.close();
    transport_.close();
    open_ = false;
}

bool LinuxDiscoveryTransport::is_open() const noexcept
{
    return open_ && receiver_.is_open() && transport_.is_open();
}

void LinuxDiscoveryTransport::set_response_handler(
    std::function<void(const discovery::DiscoveryResponse &)> handler)
{
    response_handler_ = std::move(handler);
}

core::StatusCode LinuxDiscoveryTransport::submit(const discovery::ProbeSubmission &submission)
{
    if (!is_open() || !response_handler_) {
        return core::StatusCode::PermissionDenied;
    }
    if (submission.id == 0U || submission.target.empty() || submission.packet.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    if (pending_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    const auto frame = compose_frame(submission);
    if (!frame.has_value()) {
        return core::StatusCode::PermissionDenied;
    }
    const TransportResult sent = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!sent.success()) {
        return sent.status == TransportStatus::PermissionDenied ? core::StatusCode::PermissionDenied
                                                                  : core::StatusCode::IoError;
    }
    try {
        pending_.emplace(submission.id, Pending{submission});
    } catch (const std::bad_alloc &) {
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

int LinuxDiscoveryTransport::transport_file_descriptor() const noexcept
{
    return transport_.file_descriptor();
}

int LinuxDiscoveryTransport::capture_file_descriptor() const noexcept
{
    return capture_.file_descriptor();
}

void LinuxDiscoveryTransport::on_capture_event(io::Event &event) noexcept
{
    (void)event;
    if (!is_open()) {
        return;
    }
    try {
        const ReceiverResult received = receiver_.receive();
        if (received.capture.status == CaptureStatus::Success && received.observation.has_value()) {
            dispatch_observation(*received.observation);
        }
    } catch (...) {
        // A capture callback must not let an allocation or parser exception escape the reactor.
    }
}

void LinuxDiscoveryTransport::dispatch_observation(const PacketObservation &observation) noexcept
{
    if (!response_handler_) {
        return;
    }
    std::optional<discovery::ProbeId> matched_id;
    std::vector<std::uint8_t> response_bytes;
    std::string source_address;

    if (observation.valid() && observation.ipv4.has_value() &&
        observation.ipv4->destination_address() == source_ipv4_) {
        source_address = ipv4_text(observation.ipv4->source_address());
        if (observation.icmp.has_value()) {
            const packet::ICMP &icmp = *observation.icmp;
            for (const auto &[id, pending] : pending_) {
                if (pending.submission.type == discovery::ProbeType::IcmpEcho &&
                    pending.submission.target_ipv4 == observation.ipv4->source_address() &&
                    icmp.identifier() == pending.submission.correlation_identifier &&
                    icmp.sequence() == pending.submission.correlation_sequence) {
                    matched_id = id;
                    response_bytes = icmp.serialize();
                    break;
                }
            }
        } else if (observation.tcp.has_value()) {
            const packet::TCP &tcp = *observation.tcp;
            for (const auto &[id, pending] : pending_) {
                if (pending.submission.type == discovery::ProbeType::Tcp &&
                    pending.submission.target_ipv4 == observation.ipv4->source_address() &&
                    pending.submission.port == tcp.source_port() &&
                    pending.submission.source_port == tcp.destination_port() &&
                    (!packet::has_flag(tcp.flags(), packet::TcpFlag::Ack) ||
                     tcp.acknowledgment_number() == pending.submission.sequence_number + 1U)) {
                    matched_id = id;
                    response_bytes = tcp.serialize();
                    break;
                }
            }
        }
    }

    if (!matched_id.has_value() && observation.raw_frame.size() >= packet::Ethernet::kHeaderSize + discovery::ArpMessage::kSize) {
        const auto ethernet = packet::Ethernet::parse(observation.raw_frame);
        if (ethernet.has_value() && ethernet->ether_type() == kEtherTypeArp) {
            const auto arp = discovery::ArpMessage::parse(
                std::span<const std::uint8_t>{observation.raw_frame}.subspan(packet::Ethernet::kHeaderSize));
            if (arp.has_value()) {
                for (const auto &[id, pending] : pending_) {
                    if (pending.submission.type == discovery::ProbeType::Arp &&
                        arp->sender_ipv4 == pending.submission.target_ipv4 &&
                        arp->target_ipv4 == pending.submission.source_ipv4 &&
                        arp->operation == 2U) {
                        matched_id = id;
                        response_bytes.assign(
                            observation.raw_frame.begin() + static_cast<std::ptrdiff_t>(packet::Ethernet::kHeaderSize),
                            observation.raw_frame.begin() + static_cast<std::ptrdiff_t>(
                                packet::Ethernet::kHeaderSize + discovery::ArpMessage::kSize));
                        source_address = ipv4_text(arp->sender_ipv4);
                        break;
                    }
                }
            }
        }
    }
    if (!matched_id.has_value() || response_bytes.empty()) {
        return;
    }
    const auto pending = pending_.find(*matched_id);
    if (pending == pending_.end()) {
        return;
    }
    discovery::DiscoveryResponse response;
    response.probe_id = *matched_id;
    response.source_address = std::move(source_address);
    response.bytes = std::move(response_bytes);
    response.received_at = observation.received_at;
    pending_.erase(pending);
    response_handler_(response);
}

std::optional<std::vector<std::uint8_t>> LinuxDiscoveryTransport::compose_frame(
    const discovery::ProbeSubmission &submission) const
{
    const auto target_ipv4 = discovery::parse_ipv4_address(submission.target);
    if (!target_ipv4.has_value()) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 6U> destination = {};
    if (submission.type != discovery::ProbeType::Arp && interface_name_ != "lo") {
        const auto neighbor = neighbor_mac_for(interface_name_, *target_ipv4);
        if (!neighbor.has_value()) {
            return std::nullopt;
        }
        destination = *neighbor;
    }
    if (submission.type == discovery::ProbeType::Arp) {
        const auto arp = discovery::ArpMessage::parse(submission.packet);
        if (!arp.has_value()) {
            return std::nullopt;
        }
        packet::Ethernet ethernet(
            std::array<std::uint8_t, 6U>{0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU},
            local_mac_,
            kEtherTypeArp);
        std::vector<std::uint8_t> frame(packet::Ethernet::kHeaderSize + discovery::ArpMessage::kSize, 0U);
        if (ethernet.serialize(std::span<std::uint8_t>{frame}) != core::StatusCode::Ok) {
            return std::nullopt;
        }
        const std::vector<std::uint8_t> payload = arp->serialize();
        std::copy(payload.begin(), payload.end(), frame.begin() + packet::Ethernet::kHeaderSize);
        return frame;
    }
    packet::IPv4 ipv4;
    ipv4.set_source_address(source_ipv4_);
    ipv4.set_destination_address(*target_ipv4);
    packet::Ethernet ethernet(destination, local_mac_, kEtherTypeIpv4);
    packet::Packet packet;
    packet.set_ethernet(ethernet);
    packet.set_ipv4(ipv4);
    if (submission.type == discovery::ProbeType::IcmpEcho) {
        const auto icmp = packet::ICMP::parse(submission.packet);
        if (!icmp.has_value()) {
            return std::nullopt;
        }
        ipv4.set_protocol(kIpProtocolIcmp);
        packet.set_ipv4(ipv4);
        packet.set_icmp(*icmp);
    } else if (submission.type == discovery::ProbeType::Tcp) {
        const auto tcp = packet::TCP::parse(submission.packet);
        if (!tcp.has_value()) {
            return std::nullopt;
        }
        ipv4.set_protocol(kIpProtocolTcp);
        packet.set_ipv4(ipv4);
        packet.set_tcp(*tcp);
    } else {
        return std::nullopt;
    }
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

} // namespace skan::net
