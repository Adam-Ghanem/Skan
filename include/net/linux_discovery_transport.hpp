#ifndef SKAN_NET_LINUX_DISCOVERY_TRANSPORT_HPP
#define SKAN_NET_LINUX_DISCOVERY_TRANSPORT_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "discovery/discovery_probe.hpp"
#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "net/linux_capture.hpp"
#include "net/network_scan_transport.hpp"
#include "net/linux_transport.hpp"
#include "net/packet_receiver.hpp"

namespace skan::net {

class LinuxDiscoveryTransport final : public discovery::DiscoveryTransport {
public:
    LinuxDiscoveryTransport(io::IOEngine &io_engine, std::string interface_name);
    ~LinuxDiscoveryTransport() override;

    LinuxDiscoveryTransport(const LinuxDiscoveryTransport &) = delete;
    LinuxDiscoveryTransport &operator=(const LinuxDiscoveryTransport &) = delete;

    NetworkScanResult open();
    void close() noexcept;
    bool is_open() const noexcept;
    void set_preflight_family(core::AddressFamily family) noexcept;

    void set_response_handler(std::function<void(const discovery::DiscoveryResponse &)> handler);
    core::StatusCode submit(const discovery::ProbeSubmission &submission) override;

    int transport_file_descriptor() const noexcept;
    int capture_file_descriptor() const noexcept;

private:
    struct Pending final {
        discovery::ProbeSubmission submission;
    };

    struct NeighborCacheEntry final {
        std::array<std::uint8_t, 6U> mac{};
        std::chrono::steady_clock::time_point expires_at{};
    };

    void on_capture_event(io::Event &event) noexcept;
    void dispatch_observation(const PacketObservation &observation) noexcept;
    std::optional<std::vector<std::uint8_t>> compose_frame(
        const discovery::ProbeSubmission &submission) const;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(
        const core::IpAddress &target_ip) const;
    std::optional<std::vector<std::uint8_t>> compose_neighbor_solicitation(
        const discovery::ProbeSubmission &submission) const;
    std::optional<core::IpAddress> source_address_for(const core::IpAddress &target_ip) const;

    io::IOEngine &io_engine_;
    std::string interface_name_;
    LinuxTransport transport_;
    LinuxCapture capture_;
    PacketReceiver receiver_;
    std::unordered_map<discovery::ProbeId, Pending> pending_;
    mutable std::unordered_map<core::IpAddress, NeighborCacheEntry, core::IpAddressHash> neighbor_cache_;
    std::unordered_map<discovery::ProbeId, io::TimerId> neighbor_timers_;
    std::function<void(const discovery::DiscoveryResponse &)> response_handler_;
    std::uint32_t source_ipv4_{0U};
    std::optional<core::IpAddress> source_ipv6_;
    std::array<std::uint8_t, 6U> local_mac_{};
    std::optional<core::AddressFamily> preflight_family_;
    bool open_{false};
};

} // namespace skan::net

#endif // SKAN_NET_LINUX_DISCOVERY_TRANSPORT_HPP
