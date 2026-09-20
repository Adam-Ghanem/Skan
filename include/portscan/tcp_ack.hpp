#ifndef SKAN_PORTSCAN_TCP_ACK_HPP
#define SKAN_PORTSCAN_TCP_ACK_HPP

#include "packet/tcp.hpp"
#include "portscan/port_probe.hpp"

namespace skan::portscan {

/**
 * TCP ACK firewall-mapping probe. A matching reset proves only that the target
 * was reachable through the filter; it never reports a port as open or closed.
 */
class TcpAckProbe final : public PortProbe {
public:
    ScanProbeType type() const noexcept override;
    core::StatusCode build(
        PortProbeId id,
        const core::Host &target,
        const Port &port,
        const PortScanConfig &config,
        PortSubmission &submission) const override;
    PortState timeout_state() const noexcept override;
    ScanReason timeout_reason() const noexcept override;
    core::StatusCode assess(
        const PortResponse &response,
        const PortSubmission &submission,
        PortState &state,
        ScanReason &reason) const override;

    static std::uint16_t source_port_for(PortProbeId id) noexcept;
    static std::uint32_t sequence_for(PortProbeId id) noexcept;
    static std::uint32_t acknowledgment_for(PortProbeId id) noexcept;
};

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_TCP_ACK_HPP
