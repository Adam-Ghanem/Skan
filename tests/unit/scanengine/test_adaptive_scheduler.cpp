#include <cassert>
#include <chrono>

#include "scanengine/adaptive_scheduler.hpp"

namespace {

skan::scanengine::TimingProfile test_profile(std::size_t initial, std::size_t retries)
{
    auto profile = skan::scanengine::TimingProfile::for_id(skan::scanengine::TimingProfileId::T3);
    profile.min_parallelism = 1U;
    profile.max_parallelism = initial;
    profile.initial_parallelism = initial;
    profile.minimum_timeout = std::chrono::milliseconds{1};
    profile.maximum_timeout = std::chrono::milliseconds{20};
    profile.max_retries = retries;
    profile.timeout_threshold = 1U;
    profile.recovery_threshold = 1U;
    return profile;
}

} // namespace

int main()
{
    using namespace skan::scanengine;
    skan::io::IOEngine engine;
    ScanGroup group{"completions", test_profile(2U, 0U)};
    RecordingScanTransport transport;
    ScanWorkId first = 0U;
    ScanWorkId second = 0U;
    ScanWorkId third = 0U;
    assert(group.enqueue("192.0.2.10", "tcp/22", first) == skan::core::StatusCode::Ok);
    assert(group.enqueue("192.0.2.10", "tcp/80", second) == skan::core::StatusCode::Ok);
    assert(group.enqueue("192.0.2.11", "tcp/443", third) == skan::core::StatusCode::Ok);
    AdaptiveScheduler scheduler{engine, transport, group};
    assert(scheduler.start() == skan::core::StatusCode::Ok);
    assert(scheduler.pending_count() == 2U);
    assert(transport.submissions().size() == 2U);
    std::size_t index = 0U;
    while (index < transport.submissions().size()) {
        const ScanWorkId id = transport.submissions()[index++].id;
        transport.deliver(ScanCompletion{id, ScanCompletionState::ValidResponse, std::chrono::milliseconds{5}});
    }
    assert(scheduler.complete());
    assert(group.metrics().completed == 3U);
    assert(group.metrics().rtt_samples == 3U);
    assert(group.metrics().maximum_observed_parallelism <= 2U);
    scheduler.receive(ScanCompletion{first, ScanCompletionState::ValidResponse, std::chrono::milliseconds{5}});
    assert(group.metrics().duplicate_responses == 1U);
    assert(transport.active_callback_count() == 0U);

    skan::io::IOEngine timeout_engine;
    ScanGroup timeout_group{"timeouts", test_profile(1U, 0U)};
    RecordingScanTransport timeout_transport;
    ScanWorkId timeout_id = 0U;
    assert(timeout_group.enqueue("192.0.2.12", "tcp/1", timeout_id) == skan::core::StatusCode::Ok);
    AdaptiveScheduler timeout_scheduler{timeout_engine, timeout_transport, timeout_group};
    assert(timeout_scheduler.start() == skan::core::StatusCode::Ok);
    assert(timeout_scheduler.run() == skan::core::StatusCode::Ok);
    assert(timeout_group.metrics().timed_out == 1U);
    timeout_scheduler.receive(ScanCompletion{timeout_id, ScanCompletionState::ValidResponse, std::nullopt});
    assert(timeout_group.metrics().late_responses == 1U);

    skan::io::IOEngine retry_engine;
    ScanGroup retry_group{"retry", test_profile(1U, 1U)};
    RecordingScanTransport retry_transport;
    ScanWorkId retry_id = 0U;
    assert(retry_group.enqueue("192.0.2.13", "tcp/2", retry_id) == skan::core::StatusCode::Ok);
    AdaptiveScheduler retry_scheduler{retry_engine, retry_transport, retry_group};
    assert(retry_scheduler.start() == skan::core::StatusCode::Ok);
    assert(retry_scheduler.run() == skan::core::StatusCode::Ok);
    assert(retry_transport.submissions().size() == 2U);
    assert(retry_group.metrics().retry_count == 1U);
    assert(retry_group.metrics().timed_out == 2U);

    skan::io::IOEngine cancel_engine;
    ScanGroup cancel_group{"cancel", test_profile(2U, 0U)};
    RecordingScanTransport cancel_transport;
    ScanWorkId cancel_id = 0U;
    ScanWorkId queued_id = 0U;
    assert(cancel_group.enqueue("192.0.2.14", "tcp/3", cancel_id) == skan::core::StatusCode::Ok);
    assert(cancel_group.enqueue("192.0.2.15", "tcp/4", queued_id) == skan::core::StatusCode::Ok);
    AdaptiveScheduler cancel_scheduler{cancel_engine, cancel_transport, cancel_group};
    assert(cancel_scheduler.start() == skan::core::StatusCode::Ok);
    assert(cancel_scheduler.cancel(cancel_id) == skan::core::StatusCode::Ok);
    cancel_scheduler.shutdown();
    assert(cancel_group.metrics().cancelled >= 1U);
    assert(cancel_scheduler.complete());
    return 0;
}
