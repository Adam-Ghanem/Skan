#ifndef SKAN_PORTSCAN_UDP_SCAN_HPP
#define SKAN_PORTSCAN_UDP_SCAN_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "net/linux_capture.hpp"
#include "net/linux_transport.hpp"
#include "net/packet_filter.hpp"
#include "net/packet_receiver.hpp"
#include "portscan/port_result.hpp"
#include "scanengine/scan_engine.hpp"

namespace skan::portscan {

using UDPProbeId = std::uint64_t;
using UDPScanClock = std::chrono::steady_clock;
using UDPScanTimePoint = UDPScanClock::time_point;

enum class UDPResponseKind {
    Datagram = 0,
    IcmpPortUnreachable,
    IcmpAdministrativelyProhibited,
    IcmpNetworkUnreachable,
    Malformed,
    SocketError
};

struct UDPSubmission final {
    UDPProbeId id{0U};
    std::string target;
    Port port{0U, Protocol::Udp};
    std::uint32_t source_ipv4{0U};
    std::uint32_t destination_ipv4{0U};
    std::uint16_t source_port{0U};
    std::vector<std::uint8_t> packet;
    std::vector<std::uint8_t> payload;
    std::string probe_name;
    std::size_t max_response_bytes{8192U};
    core::IpAddress source_ip{};
    core::IpAddress destination_ip{};
};

struct UDPResponse final {
    UDPProbeId id{0U};
    std::string source_address;
    std::uint32_t source_ipv4{0U};
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    UDPResponseKind kind{UDPResponseKind::Malformed};
    std::vector<std::uint8_t> bytes;
    UDPScanTimePoint received_at{};
    core::IpAddress source_ip{};
};

using UDPResponseCallback = std::function<void(const UDPResponse &)>;

class UDPScanTransport {
public:
    virtual ~UDPScanTransport() = default;

    virtual bool supports() const noexcept = 0;
    virtual core::StatusCode submit(
        const UDPSubmission &submission, UDPResponseCallback callback) = 0;
    virtual core::StatusCode cancel(UDPProbeId id) noexcept = 0;
};

class RecordingUDPTransport final : public UDPScanTransport {
public:
    bool supports() const noexcept override;
    core::StatusCode submit(const UDPSubmission &submission, UDPResponseCallback callback) override;
    core::StatusCode cancel(UDPProbeId id) noexcept override;

    const std::vector<UDPSubmission> &submissions() const noexcept;
    void deliver(const UDPResponse &response);
    void clear() noexcept;

private:
    std::vector<UDPSubmission> submissions_;
    std::unordered_map<UDPProbeId, UDPResponseCallback> callbacks_;
};

struct UDPProbeDefinition final {
    std::string name;
    std::uint16_t destination_port{0U};
    std::vector<std::uint8_t> payload;
    std::size_t max_response_bytes{8192U};
    std::string protocol_hint;
};

class UDPProbeDatabase final {
public:
    UDPProbeDatabase() = default;

    static UDPProbeDatabase built_in();
    static UDPProbeDatabase parse(std::string_view text, core::StatusCode &status);
    static UDPProbeDatabase load_file(const std::string &path, core::StatusCode &status);

    const UDPProbeDefinition *for_port(std::uint16_t port) const noexcept;
    const UDPProbeDefinition &default_probe() const noexcept;
    const std::vector<UDPProbeDefinition> &definitions() const noexcept;

private:
    std::vector<UDPProbeDefinition> definitions_;
    std::unordered_map<std::uint16_t, std::size_t> port_index_;
    std::size_t default_index_{0U};
};

class UDPScheduler final {
public:
    UDPScheduler(
        io::IOEngine &engine,
        UDPScanTransport &transport,
        UDPProbeDatabase database,
        PortScanConfig config);
    ~UDPScheduler();

    UDPScheduler(const UDPScheduler &) = delete;
    UDPScheduler &operator=(const UDPScheduler &) = delete;

    core::StatusCode submit(const core::Target &target, const std::vector<Port> &ports);
    core::StatusCode submit_default(const core::Target &target);
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;

    /** Accept a typed response from an injected or live transport. */
    void receive(const UDPResponse &response) noexcept;

    const std::vector<PortResult> &results() const noexcept;
    std::size_t queued_count() const noexcept;
    std::size_t pending_count() const noexcept;
    bool complete() const noexcept;
    core::StatusCode status() const noexcept;
    const scanengine::TimingController *timing_controller() const noexcept;

private:
    struct WorkItem final {
        core::Host host;
        Port port;
        std::size_t retry_count{0U};
        std::string probe_name;
    };

    struct Pending final {
        WorkItem work;
        UDPSubmission submission;
        UDPScanTimePoint started_at{};
        io::TimerId timer_id{0U};
    };

    core::StatusCode validate_config() const noexcept;
    bool allocate_source_port(std::uint16_t &port) noexcept;
    void release_source_port(std::uint16_t port) noexcept;
    void pump() noexcept;
    void sort_results() const noexcept;
    void append_terminal_result(
        const WorkItem &work,
        PortState state,
        ScanReason reason,
        std::optional<double> rtt_ms = std::nullopt) noexcept;
    void complete_pending(
        UDPProbeId id,
        PortState state,
        ScanReason reason,
        UDPScanTimePoint completed_at) noexcept;
    void on_timeout(UDPProbeId id) noexcept;
    void stop_if_idle() noexcept;

    io::IOEngine &engine_;
    UDPScanTransport &transport_;
    UDPProbeDatabase database_;
    PortScanConfig config_;
    std::unique_ptr<scanengine::TimingController> timing_;
    std::deque<WorkItem> queue_;
    std::unordered_map<UDPProbeId, Pending> pending_;
    static constexpr std::size_t kSourcePortSpan = 20001U;
    std::array<bool, kSourcePortSpan> source_ports_{};
    mutable std::vector<PortResult> results_;
    mutable bool results_sorted_{true};
    UDPProbeId next_id_{1U};
    std::uint16_t next_source_port_{40000U};
    core::StatusCode status_{core::StatusCode::Ok};
    bool submitted_{false};
};

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_UDP_SCAN_HPP
