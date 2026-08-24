#ifndef SKAN_DISCOVERY_ICMP_DISCOVERY_HPP
#define SKAN_DISCOVERY_ICMP_DISCOVERY_HPP

#include "discovery/discovery_probe.hpp"

namespace skan::discovery {

class IcmpDiscoveryProbe final : public DiscoveryProbe {
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

#endif // SKAN_DISCOVERY_ICMP_DISCOVERY_HPP
