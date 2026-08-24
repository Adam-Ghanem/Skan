#ifndef SKAN_SCANENGINE_SCAN_METRICS_HPP
#define SKAN_SCANENGINE_SCAN_METRICS_HPP

#include <chrono>
#include <cstddef>
#include <optional>

namespace skan::scanengine {

using ScanClock = std::chrono::steady_clock;
using ScanTimePoint = ScanClock::time_point;

struct ScanMetrics final {
    std::size_t total_queued{0U};
    std::size_t total_submitted{0U};
    std::size_t completed{0U};
    std::size_t timed_out{0U};
    std::size_t failed{0U};
    std::size_t cancelled{0U};
    std::size_t duplicate_responses{0U};
    std::size_t late_responses{0U};
    std::size_t malformed_responses{0U};
    std::size_t current_parallelism{0U};
    std::size_t maximum_observed_parallelism{0U};
    std::optional<double> current_rtt_ms;
    std::optional<double> minimum_rtt_ms;
    std::optional<double> maximum_rtt_ms;
    double average_rtt_ms{0.0};
    std::size_t rtt_samples{0U};
    std::size_t timeout_count{0U};
    std::size_t retry_count{0U};
    double estimated_drop_rate{0.0};
    ScanTimePoint started_at{};
    ScanTimePoint completed_at{};

    void record_rtt(std::chrono::milliseconds sample) noexcept;
    void set_parallelism(std::size_t current, std::size_t observed) noexcept;
    std::chrono::milliseconds elapsed() const noexcept;
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_SCAN_METRICS_HPP
