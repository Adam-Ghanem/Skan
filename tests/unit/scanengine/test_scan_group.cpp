#include <cassert>
#include <chrono>
#include <string>

#include "scanengine/scan_group.hpp"

int main()
{
    using namespace skan::scanengine;
    TimingProfile profile = TimingProfile::for_id(TimingProfileId::T3);
    profile.min_parallelism = 1U;
    profile.max_parallelism = 4U;
    profile.initial_parallelism = 2U;
    profile.max_retries = 1U;
    ScanGroup group{"alpha", profile};
    ScanGroup other{"beta", profile};
    assert(group.validate() == skan::core::StatusCode::Ok);
    assert(group.name() == "alpha");
    assert(group.queued_count() == 0U);
    ScanWorkId first = 0U;
    ScanWorkId second = 0U;
    assert(group.enqueue("192.0.2.10", "tcp/80", first) == skan::core::StatusCode::Ok);
    assert(group.enqueue("192.0.2.11", "icmp", second) == skan::core::StatusCode::Ok);
    assert(first != second);
    assert(group.metrics().total_queued == 2U);
    assert(group.state(first).value() == ScanWorkState::Queued);
    const auto item = group.next_queued();
    assert(item.has_value() && item->id == first);
    const ScanTimePoint submitted = ScanClock::now();
    assert(group.mark_submitted(first, submitted, submitted + std::chrono::seconds{1}));
    assert(group.outstanding_count() == 1U);
    assert(group.mark_completed(first));
    assert(group.state(first).value() == ScanWorkState::Completed);
    assert(group.metrics().completed == 1U);
    assert(group.cancel(second));
    assert(group.state(second).value() == ScanWorkState::Cancelled);
    assert(group.metrics().cancelled == 1U);
    assert(!group.cancel(second));
    assert(other.queued_count() == 0U);
    assert(std::string{scan_work_state_name(ScanWorkState::Completed)} == "COMPLETED");
    return 0;
}
