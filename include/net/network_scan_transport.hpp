#ifndef SKAN_NET_NETWORK_SCAN_TRANSPORT_HPP
#define SKAN_NET_NETWORK_SCAN_TRANSPORT_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/status.hpp"
#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "net/interface.hpp"
#include "net/linux_capture.hpp"
#include "net/linux_transport.hpp"
#include "net/packet_filter.hpp"
#include "net/packet_receiver.hpp"
#include "portscan/port_probe.hpp"

namespace skan::net {

enum class NetworkScanStatus {
    Success,
    InvalidConfiguration,
    InterfaceNotFound,
    RoutingUnavailable,
    PermissionDenied,
    NotSupported,
    NotOpen,
    SystemError
};

const char *network_scan_status_name(NetworkScanStatus status) noexcept;

inline core::StatusCode network_scan_status_to_status_code(NetworkScanStatus status) noexcept
{
    switch (status) {
    case NetworkScanStatus::Success:
        return core::StatusCode::Ok;
    case NetworkScanStatus::InvalidConfiguration:
    case NetworkScanStatus::InterfaceNotFound:
        return core::StatusCode::InvalidArgument;
    case NetworkScanStatus::PermissionDenied:
    case NetworkScanStatus::NotSupported:
        return core::StatusCode::PermissionDenied;
    case NetworkScanStatus::RoutingUnavailable:
    case NetworkScanStatus::NotOpen:
    case NetworkScanStatus::SystemError:
    default:
        return core::StatusCode::IoError;
    }
}

inline core::ExitCode network_scan_status_to_exit_code(NetworkScanStatus status) noexcept
{
    return core::status_to_exit_code(network_scan_status_to_status_code(status));
}

struct NetworkScanConfig final {
    std::string interface_name;
    std::size_t max_frame_size{65535U};
    bool nonblocking{true};
    std::optional<std::array<std::uint8_t, 6U>> destination_mac;
};

struct ScanSession final {
    std::uint64_t id{0U};
    NetworkInterface interface;
    std::chrono::steady_clock::time_point started_at{};
    std::size_t submitted{0U};
    std::size_t completed{0U};
    std::size_t timed_out{0U};
    std::size_t failed{0U};
    bool active{false};
    TransportStatus transport_status{TransportStatus::Closed};
    CaptureStatus capture_status{CaptureStatus::Closed};
    PreflightCategory last_preflight_category{PreflightCategory::Ready};
    core::AddressFamily last_preflight_family{core::AddressFamily::Unknown};
    int last_system_error{0};
    std::string last_error;
};

struct NetworkScanResult final {
    NetworkScanStatus status{NetworkScanStatus::Success};
    int system_error{0};
    std::string message;
    PreflightCategory category{PreflightCategory::Ready};
    core::AddressFamily family{core::AddressFamily::Unknown};

    bool success() const noexcept { return status == NetworkScanStatus::Success; }
};

/**
 * Capability-gated real TCP SYN adapter. It implements only the existing PortScanTransport
 * contract; packet construction, scheduling, timing, and result classification remain in Phase 2,
 * Phase 4, and Phase 7 components.
 */
class LinuxNetworkScanTransport final : public portscan::PortScanTransport {
public:
    LinuxNetworkScanTransport(io::IOEngine &io_engine, NetworkScanConfig config);
    ~LinuxNetworkScanTransport() override;

    LinuxNetworkScanTransport(const LinuxNetworkScanTransport &) = delete;
    LinuxNetworkScanTransport &operator=(const LinuxNetworkScanTransport &) = delete;

    NetworkScanResult open();
    void close() noexcept;
    bool is_open() const noexcept;

    bool supports(portscan::ScanProbeType probe) const noexcept override;
    core::StatusCode submit(
        const portscan::PortSubmission &submission,
        portscan::PortResponseCallback callback) override;
    core::StatusCode cancel(portscan::PortProbeId id) noexcept override;

    const ScanSession &session() const noexcept;
    int transport_file_descriptor() const noexcept;
    int capture_file_descriptor() const noexcept;

private:
    struct Pending final {
        portscan::PortSubmission submission;
        portscan::PortResponseCallback callback;
        CorrelationKey correlation_key;
    };

    void on_capture_event(io::Event &event) noexcept;
    void dispatch_observation(const PacketObservation &observation) noexcept;
    std::optional<std::vector<std::uint8_t>> compose_frame(
        const portscan::PortSubmission &submission) const;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(
        std::uint32_t target_ipv4) const;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(
        const core::IpAddress &target_ip) const;
    std::optional<core::IpAddress> source_address_for(const core::IpAddress &target_ip) const;

    io::IOEngine &io_engine_;
    NetworkScanConfig config_;
    LinuxTransport transport_;
    LinuxCapture capture_;
    PacketReceiver receiver_;
    std::unordered_map<portscan::PortProbeId, Pending> pending_;
    CorrelationTable correlation_;
    ScanSession session_;
    std::uint32_t source_ipv4_{0U};
    std::optional<core::IpAddress> source_ipv6_;
    std::array<std::uint8_t, 6U> local_mac_{};
    std::uint64_t next_session_id_{1U};
};

} // namespace skan::net

#endif // SKAN_NET_NETWORK_SCAN_TRANSPORT_HPP
