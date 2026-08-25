#ifndef SKAN_DISCOVERY_DISCOVERY_PROBE_HPP
#define SKAN_DISCOVERY_DISCOVERY_PROBE_HPP

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "discovery/discovery_types.hpp"
#include "io/io_engine.hpp"

namespace skan::discovery {

class DiscoveryContext;

struct ProbeSubmission final {
    ProbeId id{0U};
    ProbeType type{ProbeType::IcmpEcho};
    std::string target;
    std::vector<std::uint8_t> packet;
    std::uint16_t port{0U};
    std::uint16_t source_port{0U};
    std::uint16_t correlation_identifier{0U};
    std::uint16_t correlation_sequence{0U};
    std::uint32_t sequence_number{0U};
    std::uint32_t source_ipv4{0U};
    std::uint32_t target_ipv4{0U};
    core::IpAddress source_ip{};
    core::IpAddress target_ip{};
};

enum class ResponseDisposition {
    Matching = 0,
    Unrelated,
    Malformed
};

using ProbeSubmitCallback = std::function<void(const ProbeSubmission &)>;

/**
 * Transport boundary used by probes. The default implementation is deliberately offline and
 * records serialized submissions; production network transport belongs above Phase 3's scope.
 */
class DiscoveryTransport {
public:
    virtual ~DiscoveryTransport() = default;

    virtual core::StatusCode submit(const ProbeSubmission &submission) = 0;
};

class RecordingTransport final : public DiscoveryTransport {
public:
    core::StatusCode submit(const ProbeSubmission &submission) override;

    const std::vector<ProbeSubmission> &submissions() const noexcept;
    void clear() noexcept;

private:
    std::vector<ProbeSubmission> submissions_;
};

class DiscoveryProbe {
public:
    virtual ~DiscoveryProbe() = default;

    virtual ProbeType type() const noexcept = 0;
    virtual core::StatusCode build(
        ProbeId id,
        const core::Host &target,
        const DiscoveryConfig &config,
        ProbeSubmission &submission) const = 0;
    virtual ResponseDisposition assess(
        const DiscoveryResponse &response, const ProbeSubmission &submission) const = 0;
    virtual DiscoveryReason positive_reason(const DiscoveryResponse &response) const noexcept = 0;
};

} // namespace skan::discovery

#endif // SKAN_DISCOVERY_DISCOVERY_PROBE_HPP
