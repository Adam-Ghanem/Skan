#include "discovery/arp_discovery.hpp"

#include <algorithm>
#include <utility>

namespace skan::discovery {
namespace {

constexpr std::uint16_t kEthernetHardwareType = 1U;
constexpr std::uint16_t kIpv4ProtocolType = 0x0800U;
constexpr std::uint8_t kHardwareAddressLength = 6U;
constexpr std::uint8_t kProtocolAddressLength = 4U;
constexpr std::uint16_t kArpRequest = 1U;
constexpr std::uint16_t kArpReply = 2U;

void write_u16(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint16_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value & 0xFFU);
}

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                       static_cast<std::uint16_t>(bytes[offset + 1U]));
}

void write_u32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value & 0xFFU);
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

} // namespace

bool ArpMessage::validate() const noexcept
{
    return operation == kArpRequest || operation == kArpReply;
}

std::vector<std::uint8_t> ArpMessage::serialize() const
{
    if (!validate()) {
        return {};
    }
    std::vector<std::uint8_t> bytes(kSize, 0U);
    write_u16(bytes, 0U, kEthernetHardwareType);
    write_u16(bytes, 2U, kIpv4ProtocolType);
    bytes[4] = kHardwareAddressLength;
    bytes[5] = kProtocolAddressLength;
    write_u16(bytes, 6U, operation);
    std::copy(sender_mac.begin(), sender_mac.end(), bytes.begin() + 8);
    write_u32(bytes, 14U, sender_ipv4);
    std::copy(target_mac.begin(), target_mac.end(), bytes.begin() + 18);
    write_u32(bytes, 24U, target_ipv4);
    return bytes;
}

std::optional<ArpMessage> ArpMessage::parse(std::span<const std::uint8_t> bytes)
{
    if (bytes.size() < kSize || read_u16(bytes, 0U) != kEthernetHardwareType ||
        read_u16(bytes, 2U) != kIpv4ProtocolType || bytes[4] != kHardwareAddressLength ||
        bytes[5] != kProtocolAddressLength) {
        return std::nullopt;
    }

    ArpMessage message;
    message.operation = read_u16(bytes, 6U);
    std::copy_n(bytes.begin() + 8, message.sender_mac.size(), message.sender_mac.begin());
    message.sender_ipv4 = read_u32(bytes, 14U);
    std::copy_n(bytes.begin() + 18, message.target_mac.size(), message.target_mac.begin());
    message.target_ipv4 = read_u32(bytes, 24U);
    return message.validate() ? std::optional<ArpMessage>{message} : std::nullopt;
}

ProbeType ArpDiscoveryProbe::type() const noexcept
{
    return ProbeType::Arp;
}

core::StatusCode ArpDiscoveryProbe::build(
    ProbeId id,
    const core::Host &target,
    const DiscoveryConfig &config,
    ProbeSubmission &submission) const
{
    (void)config;
    const auto target_ipv4 = parse_ipv4_address(target.address);
    if (!target_ipv4.has_value() || id == 0U) {
        return core::StatusCode::InvalidArgument;
    }

    ArpMessage request;
    request.sender_mac = {0x02U, 0x53U, 0x4BU, 0x41U, 0x4EU, 0x01U};
    request.sender_ipv4 = 0U;
    request.target_ipv4 = *target_ipv4;
    request.operation = kArpRequest;

    submission = ProbeSubmission{};
    submission.id = id;
    submission.type = type();
    submission.target = target.address;
    submission.target_ipv4 = *target_ipv4;
    submission.source_ipv4 = request.sender_ipv4;
    submission.packet = request.serialize();
    return submission.packet.empty() ? core::StatusCode::InternalError : core::StatusCode::Ok;
}

ResponseDisposition ArpDiscoveryProbe::assess(
    const DiscoveryResponse &response,
    const ProbeSubmission &submission) const
{
    const auto parsed = ArpMessage::parse(std::span<const std::uint8_t>{response.bytes});
    if (!parsed.has_value()) {
        return ResponseDisposition::Malformed;
    }
    if (response.source_address != submission.target || parsed->operation != kArpReply ||
        parsed->sender_ipv4 != submission.target_ipv4 || parsed->target_ipv4 != submission.source_ipv4) {
        return ResponseDisposition::Unrelated;
    }
    return ResponseDisposition::Matching;
}

DiscoveryReason ArpDiscoveryProbe::positive_reason(const DiscoveryResponse &response) const noexcept
{
    (void)response;
    return DiscoveryReason::ArpReply;
}

} // namespace skan::discovery
