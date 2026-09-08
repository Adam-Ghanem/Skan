#ifndef SKAN_PORTSCAN_TCP_SYN_HPP
#define SKAN_PORTSCAN_TCP_SYN_HPP

#include "packet/tcp.hpp"
#include "portscan/port_probe.hpp"

namespace skan::portscan {

/**
 * Offline TCP SYN probe logic. It builds and validates TCP headers only; it does not
 * open raw sockets or transmit packets. A caller may inject a capable transport separately.
 */
class TcpSynProbe final : public PortProbe {
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
};

/**
 * Phase 34 raw-TCP flag probe used by NULL, FIN, Xmas, Window, and Maimon scans.
 * Packet scheduling, correlation, capture, and transmission stay owned by the existing
 * PortScanScheduler and PortScanTransport contracts; this class only defines TCP flags
 * and the bounded response classification for the selected reviewed scan family.
 */
class TcpFlagProbe final : public PortProbe {
public:
    explicit TcpFlagProbe(ScanProbeType type) noexcept;

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

private:
    ScanProbeType type_{ScanProbeType::TcpNull};
};

/**
 * Legacy implicit-capability query. Explicit raw-packet capability is runtime-gated by
 * net::LinuxNetworkScanTransport after the caller selects a transport and interface.
 */
bool tcp_syn_network_capability_available() noexcept;

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_TCP_SYN_HPP
