#include "scanengine/scan_metrics.hpp"

#include <algorithm>
#include <limits>

namespace skan::scanengine {
namespace {

void saturating_increment(std::size_t &value) noexcept
{
    if (value < std::numeric_limits<std::size_t>::max()) {
        ++value;
    }
}

} // namespace

void ScanMetrics::record_rtt(std::chrono::milliseconds sample) noexcept
{
    const double value = static_cast<double>(sample.count() < 0 ? 0 : sample.count());
    current_rtt_ms = value;
    minimum_rtt_ms = minimum_rtt_ms.has_value() ? std::min(*minimum_rtt_ms, value) : value;
    maximum_rtt_ms = maximum_rtt_ms.has_value() ? std::max(*maximum_rtt_ms, value) : value;
    if (rtt_samples < std::numeric_limits<std::size_t>::max()) {
        const double denominator = static_cast<double>(rtt_samples) + 1.0;
        average_rtt_ms += (value - average_rtt_ms) / denominator;
        ++rtt_samples;
    }
    if (!srtt_ms.has_value()) {
        srtt_ms = value;
        rttvar_ms = value / 2.0;
    } else {
        const double deviation = std::abs(*srtt_ms - value);
        rttvar_ms = (0.75 * *rttvar_ms) + (0.25 * deviation);
        srtt_ms = (0.875 * *srtt_ms) + (0.125 * value);
    }
    rto_ms = *srtt_ms + (4.0 * *rttvar_ms);
}

void ScanMetrics::set_parallelism(std::size_t current, std::size_t observed) noexcept
{
    current_parallelism = current;
    maximum_observed_parallelism = std::max(maximum_observed_parallelism, observed);
    active_probes = current;
    peak_active_probes = std::max(peak_active_probes, observed);
}

void ScanMetrics::record_submission(std::size_t active) noexcept
{
    saturating_increment(probes_submitted);
    saturating_increment(total_submitted);
    set_parallelism(active, std::max(active, peak_active_probes));
}

void ScanMetrics::record_completion(std::size_t active) noexcept
{
    saturating_increment(probes_completed);
    saturating_increment(completed);
    set_parallelism(active, std::max(active, peak_active_probes));
}

void ScanMetrics::record_timeout(std::size_t active) noexcept
{
    saturating_increment(probes_timed_out);
    saturating_increment(timed_out);
    saturating_increment(timeout_count);
    set_parallelism(active, std::max(active, peak_active_probes));
}

void ScanMetrics::record_failure(std::size_t active) noexcept
{
    saturating_increment(probes_failed);
    saturating_increment(failed);
    set_parallelism(active, std::max(active, peak_active_probes));
}

void ScanMetrics::record_retry() noexcept
{
    saturating_increment(retries);
    saturating_increment(retry_count);
    saturating_increment(probes_retried);
}

void ScanMetrics::record_cancellation() noexcept
{
    saturating_increment(cancelled);
    saturating_increment(probes_cancelled);
}

void ScanMetrics::record_target_failure() noexcept
{
    saturating_increment(targets_failed);
}

void ScanMetrics::record_timeout_backoff() noexcept
{
    saturating_increment(timeout_backoffs);
}

std::chrono::milliseconds ScanMetrics::elapsed() const noexcept
{
    const ScanTimePoint end = completed_at == ScanTimePoint{} ? ScanClock::now() : completed_at;
    if (started_at == ScanTimePoint{} || end <= started_at) {
        return std::chrono::milliseconds{0};
    }
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - started_at);
    return duration.count() < 0 ? std::chrono::milliseconds{0} : duration;
}

} // namespace skan::scanengine
