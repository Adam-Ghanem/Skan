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
#include "packet/icmpv6.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
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
    if (source_ipv4_ == 0U && found.interface.ipv6_addresses.empty()) {
        return {NetworkScanStatus::NotSupported, 0, "selected interface has no IPv4 or IPv6 address"};
    }
    source_ipv6_.reset();
    for (const InterfaceIPv6Address &address : found.interface.ipv6_addresses) {
        if (address.address.is_ipv6_link_local()) {
            source_ipv6_ = address.address;
            break;
        }
    }
    if (!source_ipv6_.has_value() && !found.interface.ipv6_addresses.empty()) {
        source_ipv6_ = found.interface.ipv6_addresses.front().address;
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
    for (const auto &[id, timer_id] : neighbor_timers_) {
        (void)id;
        (void)io_engine_.cancel(timer_id);
    }
    neighbor_timers_.clear();
    neighbor_cache_.clear();
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
    const auto parsed_target = core::parse_ip_address(submission.target);
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : parsed_target.value_or(core::IpAddress{});
    if (!target_ip.valid()) {
        return core::StatusCode::InvalidArgument;
    }
    discovery::ProbeSubmission effective = submission;
    effective.target_ip = target_ip;
    const auto selected_source = source_address_for(target_ip);
    if (!selected_source.has_value()) {
        return core::StatusCode::PermissionDenied;
    }
    effective.source_ip = *selected_source;
    if (target_ip.is_ipv6() && !destination_mac(target_ip).has_value()) {
        const auto solicitation = compose_neighbor_solicitation(effective);
        if (!solicitation.has_value()) {
            return core::StatusCode::PermissionDenied;
        }
        const TransportResult sent = transport_.send(std::span<const std::uint8_t>{*solicitation});
        if (!sent.success()) {
            return sent.status == TransportStatus::PermissionDenied ? core::StatusCode::PermissionDenied
                                                                      : core::StatusCode::IoError;
        }
        try {
            pending_.emplace(effective.id, Pending{effective});
            const io::TimerId timer_id = io_engine_.schedule(
                std::chrono::milliseconds{1000},
                [this, id = effective.id]() {
                    neighbor_timers_.erase(id);
                    pending_.erase(id);
                });
            neighbor_timers_.emplace(effective.id, timer_id);
        } catch (const std::bad_alloc &) {
            pending_.erase(effective.id);
            return core::StatusCode::MemoryError;
        }
        return core::StatusCode::Ok;
    }
    const auto frame = compose_frame(effective);
    if (!frame.has_value()) {
        return core::StatusCode::PermissionDenied;
    }
    const TransportResult sent = transport_.send(std::span<const std::uint8_t>{*frame});
    if (!sent.success()) {
        return sent.status == TransportStatus::PermissionDenied ? core::StatusCode::PermissionDenied
                                                                  : core::StatusCode::IoError;
    }
    try {
        pending_.emplace(effective.id, Pending{effective});
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
    if (observation.valid() && observation.ipv6.has_value() && observation.icmpv6.has_value() &&
        observation.icmpv6->type() == packet::Icmpv6Type::NeighborAdvertisement && observation.ethernet.has_value()) {
        const auto target = observation.icmpv6->neighbor_target();
        const auto options = observation.icmpv6->neighbor_options();
        if (target.has_value() && !options.empty()) {
            const core::IpAddress observed_source = core::IpAddress::from_ipv6(observation.ipv6->source_address());
            for (auto timer_iterator = neighbor_timers_.begin(); timer_iterator != neighbor_timers_.end(); ++timer_iterator) {
                const discovery::ProbeId id = timer_iterator->first;
                const io::TimerId timer_id = timer_iterator->second;
                const auto pending = pending_.find(id);
                if (pending == pending_.end() || !pending->second.submission.target_ip.is_ipv6() ||
                    options.front().type != 2U || pending->second.submission.target_ip.bytes != *target ||
                    observed_source.bytes != *target ||
                    !core::ipv6_scope_matches_interface(pending->second.submission.target_ip, interface_name_) ||
                    observation.ethernet->source() != options.front().mac) {
                    continue;
                }
                const discovery::ProbeSubmission original = pending->second.submission;
                neighbor_cache_[original.target_ip] = options.front().mac;
                (void)io_engine_.cancel(timer_id);
                neighbor_timers_.erase(timer_iterator);
                const auto frame = compose_frame(original);
                if (!frame.has_value() || !transport_.send(std::span<const std::uint8_t>{*frame}).success()) {
                    pending_.erase(id);
                }
                return;
            }
        }
    }
    std::optional<discovery::ProbeId> matched_id;
    std::vector<std::uint8_t> response_bytes;
    std::string source_address;
    core::IpAddress source_ip;

    if (observation.valid() && observation.ipv6.has_value() &&
        (observation.icmpv6.has_value() || observation.tcp.has_value())) {
        const core::IpAddress observed_source = core::IpAddress::from_ipv6(observation.ipv6->source_address());
        const core::IpAddress observed_destination = core::IpAddress::from_ipv6(observation.ipv6->destination_address());
        for (const auto &[id, pending] : pending_) {
            if (!pending.submission.target_ip.is_ipv6() || !pending.submission.source_ip.is_ipv6() ||
                pending.submission.target_ip.bytes != observed_source.bytes ||
                pending.submission.source_ip.bytes != observed_destination.bytes) {
                continue;
            }
            if (observation.icmpv6.has_value() && pending.submission.type == discovery::ProbeType::IcmpEcho &&
                observation.icmpv6->type() == packet::Icmpv6Type::EchoReply && observation.icmpv6->code() == 0U &&
                observation.icmpv6->identifier() == pending.submission.correlation_identifier &&
                observation.icmpv6->sequence() == pending.submission.correlation_sequence) {
                matched_id = id;
                response_bytes = observation.icmpv6->serialize();
            } else if (observation.tcp.has_value() && pending.submission.type == discovery::ProbeType::Tcp &&
                       observation.tcp->source_port() == pending.submission.port &&
                       observation.tcp->destination_port() == pending.submission.source_port &&
                       ((packet::has_flag(observation.tcp->flags(), packet::TcpFlag::Syn) &&
                         packet::has_flag(observation.tcp->flags(), packet::TcpFlag::Ack) &&
                         observation.tcp->acknowledgment_number() == pending.submission.sequence_number + 1U) ||
                        packet::has_flag(observation.tcp->flags(), packet::TcpFlag::Rst))) {
                matched_id = id;
                response_bytes = observation.tcp->serialize();
            }
            if (matched_id.has_value()) {
                source_ip = observed_source;
                source_ip.scope = pending.submission.target_ip.scope;
                source_address = source_ip.to_string();
                break;
            }
        }
    }

    if (!matched_id.has_value() && observation.valid() && observation.ipv4.has_value() &&
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
    response.source_ip = source_ip.valid() ? source_ip : core::IpAddress{};
    pending_.erase(pending);
    response_handler_(response);
}

std::optional<std::vector<std::uint8_t>> LinuxDiscoveryTransport::compose_frame(
    const discovery::ProbeSubmission &submission) const
{
    const core::IpAddress target_ip = submission.target_ip.valid()
                                          ? submission.target_ip
                                          : core::parse_ip_address(submission.target).value_or(core::IpAddress{});
    if (!target_ip.valid() || submission.type == discovery::ProbeType::Arp) {
        const auto target_ipv4 = discovery::parse_ipv4_address(submission.target);
        if (!target_ipv4.has_value() || submission.type != discovery::ProbeType::Arp) {
            return std::nullopt;
        }
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
    const auto destination = destination_mac(target_ip);
    if (!destination.has_value()) {
        return std::nullopt;
    }
    packet::Packet packet;
    if (target_ip.is_ipv4() && source_ipv4_ != 0U) {
        packet::IPv4 ipv4;
        ipv4.set_source_address(source_ipv4_);
        const std::uint32_t target_ipv4 = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                          (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                          static_cast<std::uint32_t>(target_ip.bytes[3]);
        ipv4.set_destination_address(target_ipv4);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, kEtherTypeIpv4));
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
    } else if (target_ip.is_ipv6() && submission.source_ip.is_ipv6()) {
        packet::IPv6 ipv6;
        ipv6.set_source_address(submission.source_ip.bytes);
        ipv6.set_destination_address(target_ip.bytes);
        packet.set_ethernet(packet::Ethernet(*destination, local_mac_, 0x86DDU));
        if (submission.type == discovery::ProbeType::IcmpEcho) {
            const auto icmpv6 = packet::ICMPv6::parse(submission.packet);
            if (!icmpv6.has_value()) {
                return std::nullopt;
            }
            ipv6.set_next_header(58U);
            packet.set_ipv6(ipv6);
            packet.set_icmpv6(*icmpv6);
        } else if (submission.type == discovery::ProbeType::Tcp) {
            const auto tcp = packet::TCP::parse(submission.packet);
            if (!tcp.has_value()) {
                return std::nullopt;
            }
            ipv6.set_next_header(kIpProtocolTcp);
            packet.set_ipv6(ipv6);
            packet.set_tcp(*tcp);
        } else {
            return std::nullopt;
        }
    } else {
        return std::nullopt;
    }
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

std::optional<std::array<std::uint8_t, 6U>> LinuxDiscoveryTransport::destination_mac(
    const core::IpAddress &target_ip) const
{
    if (interface_name_ == "lo") {
        return std::array<std::uint8_t, 6U>{};
    }
    if (target_ip.is_ipv6()) {
        const auto cached = neighbor_cache_.find(target_ip);
        if (cached != neighbor_cache_.end()) {
            return cached->second;
        }
        return std::nullopt;
    }
    if (target_ip.is_ipv4()) {
        const std::uint32_t address = (static_cast<std::uint32_t>(target_ip.bytes[0]) << 24U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[1]) << 16U) |
                                      (static_cast<std::uint32_t>(target_ip.bytes[2]) << 8U) |
                                      static_cast<std::uint32_t>(target_ip.bytes[3]);
        return neighbor_mac_for(interface_name_, address);
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> LinuxDiscoveryTransport::compose_neighbor_solicitation(
    const discovery::ProbeSubmission &submission) const
{
    if (!submission.target_ip.is_ipv6() || !submission.source_ip.is_ipv6() ||
        !submission.target_ip.is_ipv6_link_local() ||
        !core::ipv6_scope_matches_interface(submission.target_ip, interface_name_)) {
        return std::nullopt;
    }
    const auto message = packet::ICMPv6::make_neighbor_solicitation(submission.target_ip.bytes, local_mac_);
    if (!message.has_value()) {
        return std::nullopt;
    }
    const auto multicast = packet::ICMPv6::solicited_node_multicast(submission.target_ip.bytes);
    packet::IPv6 ipv6;
    ipv6.set_next_header(58U);
    ipv6.set_hop_limit(255U);
    ipv6.set_source_address(submission.source_ip.bytes);
    ipv6.set_destination_address(multicast);
    packet::Packet packet;
    packet.set_ethernet(packet::Ethernet(packet::ICMPv6::ethernet_multicast(multicast), local_mac_, 0x86DDU));
    packet.set_ipv6(ipv6);
    packet.set_icmpv6(*message);
    std::vector<std::uint8_t> frame = packet.serialize();
    return frame.empty() ? std::nullopt : std::optional<std::vector<std::uint8_t>>{std::move(frame)};
}

std::optional<core::IpAddress> LinuxDiscoveryTransport::source_address_for(
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
        if (!core::ipv6_scope_matches_interface(target_ip, interface_name_)) {
            return std::nullopt;
        }
        source.scope = target_ip.scope;
    }
    return source;
}

} // namespace skan::net
