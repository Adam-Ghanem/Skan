#ifndef SKAN_NET_UDP_NETWORK_SCAN_TRANSPORT_HPP
#define SKAN_NET_UDP_NETWORK_SCAN_TRANSPORT_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "net/network_scan_transport.hpp"
#include "portscan/udp_scan.hpp"

namespace skan::net {

/** Explicit Linux AF_PACKET UDP adapter. It never falls back to offline transport. */
class LinuxUDPScanTransport final : public portscan::UDPScanTransport {
public:
    LinuxUDPScanTransport(io::IOEngine &io_engine, NetworkScanConfig config);
    ~LinuxUDPScanTransport() override;

    LinuxUDPScanTransport(const LinuxUDPScanTransport &) = delete;
    LinuxUDPScanTransport &operator=(const LinuxUDPScanTransport &) = delete;

    NetworkScanResult open();
    void close() noexcept;
    bool is_open() const noexcept;

    bool supports() const noexcept override;
    core::StatusCode submit(
        const portscan::UDPSubmission &submission,
        portscan::UDPResponseCallback callback) override;
    core::StatusCode cancel(portscan::UDPProbeId id) noexcept override;

    const ScanSession &session() const noexcept;
    int transport_file_descriptor() const noexcept;
    int capture_file_descriptor() const noexcept;

private:
    struct Pending final {
        portscan::UDPSubmission submission;
        portscan::UDPResponseCallback callback;
    };

    void on_capture_event(io::Event &event) noexcept;
    void dispatch_observation(const PacketObservation &observation) noexcept;
    std::optional<std::vector<std::uint8_t>> compose_frame(
        const portscan::UDPSubmission &submission) const;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(
        std::uint32_t target_ipv4) const;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(
        const core::IpAddress &target_ip) const;
    std::optional<core::IpAddress> source_address_for(const core::IpAddress &target_ip) const;
    std::optional<portscan::UDPProbeId> match_udp(
        const PacketObservation &observation) const noexcept;
    std::optional<portscan::UDPProbeId> match_icmp(
        const PacketObservation &observation) const noexcept;
    std::optional<portscan::UDPProbeId> match_icmpv6(
        const PacketObservation &observation) const noexcept;

    io::IOEngine &io_engine_;
    NetworkScanConfig config_;
    LinuxTransport transport_;
    LinuxCapture capture_;
    PacketReceiver receiver_;
    std::unordered_map<portscan::UDPProbeId, Pending> pending_;
    ScanSession session_;
    std::uint32_t source_ipv4_{0U};
    std::optional<core::IpAddress> source_ipv6_;
    std::array<std::uint8_t, 6U> local_mac_{};
    std::uint64_t next_session_id_{1U};
};

} // namespace skan::net

#endif // SKAN_NET_UDP_NETWORK_SCAN_TRANSPORT_HPP
