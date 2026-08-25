#ifndef SKAN_DETECT_SERVICE_SCHEDULER_HPP
#define SKAN_DETECT_SERVICE_SCHEDULER_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "detect/service_db.hpp"
#include "detect/service_matcher.hpp"
#include "detect/service_probe.hpp"
#include "io/io_engine.hpp"
#include "portscan/port_result.hpp"
#include "scanengine/scan_engine.hpp"

namespace skan::detect {

class ServiceScheduler final {
public:
    /**
     * The probe database is borrowed and must outlive this scheduler. Use
     * ServiceDetector when value ownership is required by the caller.
     */
    ServiceScheduler(
        io::IOEngine &engine,
        ServiceTransport &transport,
        const ServiceProbeDatabase &database,
        ServiceDetectionConfig config);
    ~ServiceScheduler();

    ServiceScheduler(const ServiceScheduler &) = delete;
    ServiceScheduler &operator=(const ServiceScheduler &) = delete;

    core::StatusCode submit(const std::vector<portscan::PortResult> &open_ports);
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;
    void receive(const ServiceResponse &response) noexcept;

    const std::vector<ServiceResult> &results() const noexcept;
    std::size_t pending_count() const noexcept;
    std::size_t queued_count() const noexcept;
    bool complete() const noexcept;
    core::StatusCode status() const noexcept;
    const scanengine::TimingController *timing_controller() const noexcept;

private:
    struct WorkItem final {
        portscan::PortResult port_result;
        std::vector<std::size_t> probe_indices;
        std::size_t next_probe{0U};
        std::size_t retry_count{0U};
    };

    struct Pending final {
        WorkItem work;
        ServiceSubmission submission;
        std::size_t probe_index{0U};
        std::string response;
        DetectionTimePoint started_at{};
        io::TimerId timer_id{0U};
    };

    core::StatusCode validate_config() const noexcept;
    void sort_results() const noexcept;
    void pump() noexcept;
    void start_or_retry(WorkItem work) noexcept;
    void complete_pending(
        ServiceProbeId id,
        DetectionState state,
        DetectionError error,
        const ServiceMatchResult *match,
        DetectionTimePoint completed_at) noexcept;
    void on_timeout(ServiceProbeId id) noexcept;
    void append_result(
        const portscan::PortResult &port_result,
        const ServiceProbeDefinition *probe,
        DetectionState state,
        DetectionError error,
        const ServiceMatchResult *match,
        std::optional<double> rtt_ms = std::nullopt) noexcept;
    void stop_if_idle() noexcept;

    io::IOEngine &engine_;
    ServiceTransport &transport_;
    const ServiceProbeDatabase &database_;
    ServiceDetectionConfig config_;
    ServiceMatcher matcher_;
    std::unique_ptr<scanengine::TimingController> timing_;
    std::deque<WorkItem> queue_;
    std::unordered_map<ServiceProbeId, Pending> pending_;
    mutable std::vector<ServiceResult> results_;
    mutable bool results_sorted_{true};
    ServiceProbeId next_id_{1U};
    core::StatusCode status_{core::StatusCode::Ok};
    bool submitted_{false};
};

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_SCHEDULER_HPP
