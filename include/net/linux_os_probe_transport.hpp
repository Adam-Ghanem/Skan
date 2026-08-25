#ifndef SKAN_NET_LINUX_OS_PROBE_TRANSPORT_HPP
#define SKAN_NET_LINUX_OS_PROBE_TRANSPORT_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "net/interface.hpp"
#include "net/linux_capture.hpp"
#include "net/linux_transport.hpp"
#include "net/network_scan_transport.hpp"
#include "net/packet_filter.hpp"
#include "net/packet_receiver.hpp"
#include "osdetect/os_probe.hpp"

namespace skan::net {

class LinuxOSProbeTransport final : public osdetect::OSProbeTransport {
public:
    LinuxOSProbeTransport(io::IOEngine &engine, NetworkScanConfig config);
    ~LinuxOSProbeTransport() override;

    LinuxOSProbeTransport(const LinuxOSProbeTransport &) = delete;
    LinuxOSProbeTransport &operator=(const LinuxOSProbeTransport &) = delete;

    NetworkScanResult open();
    void close() noexcept;
    bool is_open() const noexcept;

    bool supports(osdetect::OSProbeType type) const noexcept override;
    std::string local_source_address() const override;
    core::StatusCode submit(osdetect::OSProbeSubmission submission, osdetect::OSProbeCallback callback) override;
    core::StatusCode cancel(osdetect::OSProbeId id) noexcept override;

    const ScanSession &session() const noexcept;
    int transport_file_descriptor() const noexcept;
    int capture_file_descriptor() const noexcept;

private:
    struct Pending final {
        osdetect::OSProbeSubmission submission;
        osdetect::OSProbeCallback callback;
    };

    struct Correlation final {
        std::uint32_t target_ipv4{0U};
        std::uint16_t source_port{0U};
        std::uint16_t destination_port{0U};
        std::uint32_t sequence{0U};
        std::uint32_t identity{0U};
        std::uint8_t protocol{0U};

        bool operator==(const Correlation &other) const noexcept
        {
            return target_ipv4 == other.target_ipv4 && source_port == other.source_port &&
                   destination_port == other.destination_port && sequence == other.sequence &&
                   identity == other.identity && protocol == other.protocol;
        }
    };

    struct CorrelationHash final {
        std::size_t operator()(const Correlation &value) const noexcept;
    };

    void on_capture_event(io::Event &event) noexcept;
    void dispatch_observation(const PacketObservation &observation) noexcept;
    std::optional<std::vector<std::uint8_t>> compose_frame(const osdetect::OSProbeSubmission &submission) const;
    std::optional<osdetect::OSProbeId> match_tcp(const PacketObservation &observation) const noexcept;
    std::optional<osdetect::OSProbeId> match_icmp(const PacketObservation &observation) const noexcept;
    std::optional<osdetect::OSProbeId> match_udp(const PacketObservation &observation) const noexcept;
    std::optional<std::array<std::uint8_t, 6U>> destination_mac(std::uint32_t target_ipv4) const;

    io::IOEngine &engine_;
    NetworkScanConfig config_;
    LinuxTransport transport_;
    LinuxCapture capture_;
    PacketReceiver receiver_;
    std::unordered_map<osdetect::OSProbeId, Pending> pending_;
    std::unordered_map<Correlation, osdetect::OSProbeId, CorrelationHash> correlations_;
    ScanSession session_;
    std::uint32_t source_ipv4_{0U};
    std::array<std::uint8_t, 6U> local_mac_{};
    std::uint64_t next_session_id_{1U};
};

} // namespace skan::net

#endif // SKAN_NET_LINUX_OS_PROBE_TRANSPORT_HPP
