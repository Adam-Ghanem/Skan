#ifndef SKAN_DISCOVERY_ARP_DISCOVERY_HPP
#define SKAN_DISCOVERY_ARP_DISCOVERY_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "discovery/discovery_probe.hpp"

namespace skan::discovery {

struct ArpMessage final {
    static constexpr std::size_t kSize = 28U;

    std::array<std::uint8_t, 6U> sender_mac{};
    std::uint32_t sender_ipv4{0U};
    std::array<std::uint8_t, 6U> target_mac{};
    std::uint32_t target_ipv4{0U};
    std::uint16_t operation{1U};

    bool validate() const noexcept;
    std::vector<std::uint8_t> serialize() const;
    static std::optional<ArpMessage> parse(std::span<const std::uint8_t> bytes);
};

class ArpDiscoveryProbe final : public DiscoveryProbe {
public:
    ProbeType type() const noexcept override;

    core::StatusCode build(
        ProbeId id,
        const core::Host &target,
        const DiscoveryConfig &config,
        ProbeSubmission &submission) const override;

    ResponseDisposition assess(
        const DiscoveryResponse &response, const ProbeSubmission &submission) const override;
    DiscoveryReason positive_reason(const DiscoveryResponse &response) const noexcept override;
};

} // namespace skan::discovery

#endif // SKAN_DISCOVERY_ARP_DISCOVERY_HPP
