#ifndef SKAN_OSDETECT_OS_SCHEDULER_HPP
#define SKAN_OSDETECT_OS_SCHEDULER_HPP

#include <cstddef>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "io/io_engine.hpp"
#include "osdetect/os_matcher.hpp"
#include "osdetect/os_probe.hpp"
#include "portscan/port_result.hpp"
#include "scanengine/scan_engine.hpp"

namespace skan::osdetect {

struct OSSchedulerConfig final {
    std::chrono::milliseconds timeout{1000};
    std::size_t max_outstanding{8U};
    std::uint16_t probe_port{80U};
    std::string source_address{};
    std::uint16_t udp_probe_port{161U};
    std::vector<std::uint8_t> udp_probe_payload{0x53U, 0x4BU, 0x41U, 0x4EU};
    std::size_t max_results{3U};
    bool adaptive_timing{false};
    scanengine::TimingProfile timing_profile{};
};

class OSScheduler final {
public:
    /**
     * The database is borrowed and must outlive this scheduler. Use OSDetector
     * when value ownership is required by the caller.
     */
    OSScheduler(
        io::IOEngine &engine,
        OSProbeTransport &transport,
        const db::OSFingerprintDatabase &database,
        OSSchedulerConfig config);
    ~OSScheduler();

    OSScheduler(const OSScheduler &) = delete;
    OSScheduler &operator=(const OSScheduler &) = delete;

    core::StatusCode submit(
        const core::Target &target,
        const std::vector<portscan::PortResult> &port_results);
    void receive(const OSProbeResponse &response) noexcept;
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;
    void stop() noexcept;

    bool complete() const noexcept;
    std::size_t pending_count() const noexcept;
    core::StatusCode status() const noexcept;
    const std::optional<OSDetectionResult> &result() const noexcept;
    const scanengine::TimingController *timing_controller() const noexcept;

private:
    struct WorkItem final {
        core::Host host;
        portscan::Port port;
        OSProbeType type{OSProbeType::TcpSynStandard};
        std::size_t retry_count{0U};
    };

    struct Pending final {
        WorkItem work;
        OSProbeSubmission submission;
        OSProbeTimePoint sent_at{};
        io::TimerId timer_id{0U};
    };

    void pump() noexcept;
    void start_or_retry(WorkItem work) noexcept;
    void on_timeout(OSProbeId id) noexcept;
    void finish_probe(
        Pending &pending,
        const OSProbeAssessment &assessment,
        OSProbeTimePoint received_at) noexcept;
    void finish_terminal() noexcept;
    void append_observation(const OSProbeAssessment &assessment);
    void append_terminal_status(OSProbeType type, OSProbeStatus status);
    void emit_result(
        OSDetectionState state,
        OSDetectionError error) noexcept;
    void cancel_all() noexcept;

    io::IOEngine &engine_;
    OSProbeTransport &transport_;
    const db::OSFingerprintDatabase &database_;
    OSSchedulerConfig config_;
    OSMatcher matcher_;
    std::unique_ptr<scanengine::TimingController> timing_;
    std::vector<std::unique_ptr<OSProbe>> probes_;
    std::deque<WorkItem> queue_;
    std::unordered_map<OSProbeId, Pending> pending_;
    std::unordered_set<OSProbeId> completed_ids_;
    std::unordered_set<OSProbeId> expired_ids_;
    std::optional<ObservedOSFingerprint> observed_;
    std::optional<OSDetectionResult> result_;
    std::string target_;
    core::StatusCode status_{core::StatusCode::Ok};
    OSProbeId next_id_{1U};
    bool submitted_{false};
    std::size_t generated_count_{0U};
    std::size_t sent_count_{0U};
    std::size_t response_count_{0U};
    std::size_t timeout_count_{0U};
    std::size_t unsupported_count_{0U};
    std::size_t malformed_count_{0U};
    double rtt_sum_ms_{0.0};
    std::size_t rtt_count_{0U};
};

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_SCHEDULER_HPP
