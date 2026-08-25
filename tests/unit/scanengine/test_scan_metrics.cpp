#include <cassert>
#include <chrono>
#include <cstddef>

#include "scanengine/scan_metrics.hpp"

int main()
{
    using namespace skan::scanengine;
    ScanMetrics metrics;
    assert(metrics.elapsed() == std::chrono::milliseconds{0});
    metrics.record_rtt(std::chrono::milliseconds{10});
    metrics.record_rtt(std::chrono::milliseconds{30});
    assert(metrics.rtt_samples == 2U);
    assert(metrics.minimum_rtt_ms.value() == 10.0);
    assert(metrics.maximum_rtt_ms.value() == 30.0);
    assert(metrics.average_rtt_ms == 20.0);
    metrics.set_parallelism(3U, 5U);
    metrics.set_parallelism(2U, 4U);
    assert(metrics.current_parallelism == 2U);
    assert(metrics.maximum_observed_parallelism == 5U);
    metrics.started_at = ScanClock::now();
    metrics.completed_at = metrics.started_at + std::chrono::milliseconds{25};
    assert(metrics.elapsed() == std::chrono::milliseconds{25});

    ScanMetrics large;
    for (std::size_t index = 0U; index < 10000U; ++index) {
        large.record_rtt(std::chrono::milliseconds{1000});
    }
    assert(large.rtt_samples == 10000U);
    assert(large.average_rtt_ms == 1000.0);
    assert(large.minimum_rtt_ms.value() == 1000.0);
    assert(large.maximum_rtt_ms.value() == 1000.0);
    return 0;
}
