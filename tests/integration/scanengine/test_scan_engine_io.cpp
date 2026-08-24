#include <cassert>
#include <chrono>
#include <cstddef>
#include <string>

#include "scanengine/adaptive_scheduler.hpp"

namespace {

skan::scanengine::TimingProfile profile()
{
    auto value = skan::scanengine::TimingProfile::for_id(skan::scanengine::TimingProfileId::T3);
    value.min_parallelism = 1U;
    value.max_parallelism = 16U;
    value.initial_parallelism = 4U;
    value.minimum_timeout = std::chrono::milliseconds{1};
    value.maximum_timeout = std::chrono::milliseconds{20};
    value.recovery_threshold = 2U;
    value.timeout_threshold = 2U;
    return value;
}

} // namespace

int main()
{
    using namespace skan::scanengine;
    skan::io::IOEngine engine;
    ScanGroup group{"stress", profile()};
    for (std::size_t index = 0U; index < 1000U; ++index) {
        ScanWorkId id = 0U;
        assert(group.enqueue("192.0.2." + std::to_string((index % 200U) + 1U), "tcp/" + std::to_string(index), id) ==
               skan::core::StatusCode::Ok);
    }
    RecordingScanTransport transport;
    AdaptiveScheduler scheduler{engine, transport, group};
    assert(scheduler.start() == skan::core::StatusCode::Ok);
    assert(scheduler.pending_count() <= 16U);
    std::size_t delivered = 0U;
    while (delivered < transport.submissions().size()) {
        const ScanWorkId id = transport.submissions()[delivered++].id;
        transport.deliver(ScanCompletion{id, ScanCompletionState::ValidResponse, std::chrono::milliseconds{2}});
        assert(scheduler.pending_count() <= 16U);
    }
    assert(scheduler.complete());
    assert(group.metrics().total_queued == 1000U);
    assert(group.metrics().completed == 1000U);
    assert(group.metrics().timed_out == 0U);
    assert(group.metrics().maximum_observed_parallelism <= 16U);
    assert(transport.active_callback_count() == 0U);

    skan::io::IOEngine timeout_engine;
    ScanGroup timeout_group{"io-timeout", profile()};
    ScanWorkId timeout_id = 0U;
    assert(timeout_group.enqueue("192.0.2.1", "icmp", timeout_id) == skan::core::StatusCode::Ok);
    RecordingScanTransport timeout_transport;
    AdaptiveScheduler timeout_scheduler{timeout_engine, timeout_transport, timeout_group};
    assert(timeout_scheduler.start() == skan::core::StatusCode::Ok);
    assert(timeout_scheduler.run() == skan::core::StatusCode::Ok);
    assert(timeout_group.metrics().timed_out == 1U);
    return 0;
}
