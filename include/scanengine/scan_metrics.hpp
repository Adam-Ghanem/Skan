#ifndef SKAN_SCANENGINE_SCAN_METRICS_HPP
#define SKAN_SCANENGINE_SCAN_METRICS_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace skan::scanengine {

using ScanClock = std::chrono::steady_clock;
using ScanTimePoint = ScanClock::time_point;

struct ScanMetrics final {
    // Generic work counters. The legacy names remain part of the public contract.
    std::size_t total_queued{0U};
    std::size_t targets_total{0U};
    std::size_t targets_completed{0U};
    std::size_t targets_failed{0U};
    std::size_t probes_submitted{0U};
    std::size_t probes_completed{0U};
    std::size_t probes_timed_out{0U};
    std::size_t probes_failed{0U};
    std::size_t probes_cancelled{0U};
    std::size_t probes_retried{0U};
    std::size_t retries{0U};
    std::size_t bytes_sent{0U};
    std::size_t bytes_received{0U};
    std::size_t total_submitted{0U};
    std::size_t completed{0U};
    std::size_t timed_out{0U};
    std::size_t failed{0U};
    std::size_t cancelled{0U};
    std::size_t duplicate_responses{0U};
    std::size_t late_responses{0U};
    std::size_t malformed_responses{0U};
    std::size_t parse_errors{0U};
    std::size_t correlation_misses{0U};
    std::size_t active_probes{0U};
    std::size_t peak_active_probes{0U};
    std::size_t current_parallelism{0U};
    std::size_t maximum_observed_parallelism{0U};
    std::optional<double> current_rtt_ms;
    std::optional<double> minimum_rtt_ms;
    std::optional<double> maximum_rtt_ms;
    std::optional<double> srtt_ms;
    std::optional<double> rttvar_ms;
    std::optional<double> rto_ms;
    double average_rtt_ms{0.0};
    std::size_t rtt_samples{0U};
    std::size_t timeout_count{0U};
    std::size_t retry_count{0U};
    std::size_t timeout_backoffs{0U};
    double estimated_drop_rate{0.0};
    ScanTimePoint started_at{};
    ScanTimePoint completed_at{};
    // Indexed by the stable stage order: discovery, port, UDP, service, OS, output.
    std::array<double, 6U> stage_duration_ms{};

    void record_rtt(std::chrono::milliseconds sample) noexcept;
    void set_parallelism(std::size_t current, std::size_t observed) noexcept;
    void record_submission(std::size_t active) noexcept;
    void record_completion(std::size_t active) noexcept;
    void record_timeout(std::size_t active) noexcept;
    void record_failure(std::size_t active) noexcept;
    void record_retry() noexcept;
    void record_cancellation() noexcept;
    void record_target_failure() noexcept;
    void record_timeout_backoff() noexcept;
    std::chrono::milliseconds elapsed() const noexcept;
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_SCAN_METRICS_HPP
