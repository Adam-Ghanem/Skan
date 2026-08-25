#include "scanengine/scan_metrics.hpp"

#include <algorithm>
#include <limits>

namespace skan::scanengine {

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
}

void ScanMetrics::set_parallelism(std::size_t current, std::size_t observed) noexcept
{
    current_parallelism = current;
    maximum_observed_parallelism = std::max(maximum_observed_parallelism, observed);
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
