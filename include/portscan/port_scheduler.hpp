#ifndef SKAN_PORTSCAN_PORT_SCHEDULER_HPP
#define SKAN_PORTSCAN_PORT_SCHEDULER_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "discovery/discovery_types.hpp"
#include "io/io_engine.hpp"
#include "portscan/port_probe.hpp"
#include "scanengine/scan_engine.hpp"

namespace skan::portscan {

class PortScanScheduler final {
public:
    PortScanScheduler(
        io::IOEngine &engine,
        PortScanTransport &transport,
        PortScanConfig config);
    ~PortScanScheduler();

    PortScanScheduler(const PortScanScheduler &) = delete;
    PortScanScheduler &operator=(const PortScanScheduler &) = delete;

    core::StatusCode submit(const core::Target &target, const std::vector<Port> &ports);
    core::StatusCode submit_default(const core::Target &target);
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;

    /** Accept a response from an injected transport; invalid/unrelated responses are ignored. */
    void receive(const PortResponse &response) noexcept;

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
    };

    struct Pending final {
        WorkItem work;
        PortSubmission submission;
        PortScanTimePoint started_at{};
        io::TimerId timer_id{0U};
    };

    core::StatusCode validate_config() const noexcept;
    void sort_results() const noexcept;
    void pump() noexcept;
    void append_terminal_result(
        const WorkItem &work,
        ScanProbeType probe,
        PortState state,
        ScanReason reason,
        std::optional<double> rtt_ms = std::nullopt) noexcept;
    void complete_pending(
        PortProbeId id,
        PortState state,
        ScanReason reason,
        PortScanTimePoint completed_at) noexcept;
    void on_timeout(PortProbeId id) noexcept;
    void stop_if_idle() noexcept;

    io::IOEngine &engine_;
    PortScanTransport &transport_;
    PortScanConfig config_;
    std::unique_ptr<PortProbe> probe_;
    std::unique_ptr<scanengine::TimingController> timing_;
    std::deque<WorkItem> queue_;
    std::unordered_map<PortProbeId, Pending> pending_;
    mutable std::vector<PortResult> results_;
    mutable bool results_sorted_{true};
    PortProbeId next_id_{1U};
    core::StatusCode status_{core::StatusCode::Ok};
    bool submitted_{false};
};

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_PORT_SCHEDULER_HPP
