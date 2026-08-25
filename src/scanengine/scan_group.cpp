#include "scanengine/scan_group.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace skan::scanengine {
namespace {

std::size_t outstanding_metric(const ScanMetrics &metrics) noexcept
{
    std::size_t outstanding = metrics.total_submitted;
    const auto subtract = [&outstanding](std::size_t value) noexcept {
        outstanding = value > outstanding ? 0U : outstanding - value;
    };
    subtract(metrics.completed);
    subtract(metrics.timed_out);
    subtract(metrics.failed);
    subtract(metrics.cancelled);
    return outstanding;
}

} // namespace

ScanGroup::ScanGroup(std::string name, TimingProfile profile)
    : name_(std::move(name)),
      profile_(profile),
      rtt_(RttEstimatorConfig{profile.minimum_timeout, profile.maximum_timeout, 0.125, 0.25, profile.rtt_multiplier}),
      congestion_(CongestionConfig{profile.min_parallelism,
                                   profile.max_parallelism,
                                   profile.initial_parallelism,
                                   profile.timeout_threshold,
                                   profile.recovery_threshold,
                                   profile.backoff_factor,
                                   profile.drop_rate_alpha})
{
}

core::StatusCode ScanGroup::validate() const noexcept
{
    return profile_.validate() == core::StatusCode::Ok && congestion_.valid()
               ? core::StatusCode::Ok
               : core::StatusCode::InvalidArgument;
}

core::StatusCode ScanGroup::enqueue(std::string target, std::string protocol_metadata, ScanWorkId &id)
{
    if (validate() != core::StatusCode::Ok || next_id_ == 0U) {
        return core::StatusCode::InvalidArgument;
    }
    ScanWorkItem item;
    item.id = next_id_++;
    item.target = std::move(target);
    item.protocol_metadata = std::move(protocol_metadata);
    item.created_at = ScanClock::now();
    const core::StatusCode result = enqueue(std::move(item));
    if (result == core::StatusCode::Ok) {
        id = next_id_ - 1U;
    }
    return result;
}

core::StatusCode ScanGroup::enqueue(ScanWorkItem item)
{
    if (validate() != core::StatusCode::Ok || item.id == 0U || item.state != ScanWorkState::Queued ||
        items_.find(item.id) != items_.end()) {
        return core::StatusCode::InvalidArgument;
    }
    if (item.created_at == ScanTimePoint{}) {
        item.created_at = ScanClock::now();
    }
    try {
        items_.emplace(item.id, std::move(item));
        queue_.push_back(item.id);
        ++metrics_.total_queued;
        if (next_id_ <= queue_.back() && queue_.back() < std::numeric_limits<ScanWorkId>::max()) {
            next_id_ = queue_.back() + 1U;
        }
    } catch (const std::bad_alloc &) {
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

std::optional<ScanWorkItem> ScanGroup::next_queued()
{
    while (!queue_.empty()) {
        const ScanWorkId id = queue_.front();
        queue_.pop_front();
        const auto iterator = items_.find(id);
        if (iterator != items_.end() && iterator->second.state == ScanWorkState::Queued) {
            return iterator->second;
        }
    }
    return std::nullopt;
}

bool ScanGroup::requeue_for_retry(ScanWorkItem item) noexcept
{
    const auto iterator = items_.find(item.id);
    if (iterator == items_.end() ||
        (iterator->second.state != ScanWorkState::TimedOut && iterator->second.state != ScanWorkState::Failed) ||
        item.retry_count >= profile_.max_retries) {
        return false;
    }
    item.state = ScanWorkState::Queued;
    ++item.retry_count;
    iterator->second = std::move(item);
    try {
        queue_.push_back(iterator->first);
    } catch (const std::bad_alloc &) {
        iterator->second.state = ScanWorkState::Failed;
        ++metrics_.failed;
        return false;
    }
    ++metrics_.retry_count;
    return true;
}

bool ScanGroup::cancel(ScanWorkId id) noexcept
{
    const auto iterator = items_.find(id);
    if (iterator == items_.end() || iterator->second.state == ScanWorkState::Completed ||
        iterator->second.state == ScanWorkState::Cancelled || iterator->second.state == ScanWorkState::Failed) {
        return false;
    }
    iterator->second.state = ScanWorkState::Cancelled;
    ++metrics_.cancelled;
    return true;
}

void ScanGroup::cancel_all() noexcept
{
    for (auto &entry : items_) {
        if (entry.second.state == ScanWorkState::Queued || entry.second.state == ScanWorkState::Submitted) {
            entry.second.state = ScanWorkState::Cancelled;
            ++metrics_.cancelled;
        }
    }
    queue_.clear();
}

bool ScanGroup::mark_submitted(ScanWorkId id, ScanTimePoint submitted_at, ScanTimePoint deadline) noexcept
{
    const auto iterator = items_.find(id);
    if (iterator == items_.end() || iterator->second.state != ScanWorkState::Queued) {
        return false;
    }
    iterator->second.state = ScanWorkState::Submitted;
    iterator->second.submitted_at = submitted_at;
    iterator->second.deadline = deadline;
    ++metrics_.total_submitted;
    const std::size_t outstanding = outstanding_metric(metrics_);
    metrics_.set_parallelism(outstanding, outstanding);
    return true;
}

bool ScanGroup::mark_completed(ScanWorkId id) noexcept
{
    const auto iterator = items_.find(id);
    if (iterator == items_.end() || iterator->second.state != ScanWorkState::Submitted) {
        return false;
    }
    iterator->second.state = ScanWorkState::Completed;
    ++metrics_.completed;
    update_parallelism();
    return true;
}

bool ScanGroup::mark_timed_out(ScanWorkId id) noexcept
{
    const auto iterator = items_.find(id);
    if (iterator == items_.end() || iterator->second.state != ScanWorkState::Submitted) {
        return false;
    }
    iterator->second.state = ScanWorkState::TimedOut;
    ++metrics_.timed_out;
    ++metrics_.timeout_count;
    update_parallelism();
    return true;
}

bool ScanGroup::mark_failed(ScanWorkId id) noexcept
{
    const auto iterator = items_.find(id);
    if (iterator == items_.end() || iterator->second.state != ScanWorkState::Submitted) {
        return false;
    }
    iterator->second.state = ScanWorkState::Failed;
    ++metrics_.failed;
    update_parallelism();
    return true;
}

void ScanGroup::update_parallelism() noexcept
{
    const std::size_t outstanding = outstanding_metric(metrics_);
    metrics_.set_parallelism(outstanding, outstanding);
}

const std::string &ScanGroup::name() const noexcept { return name_; }
const TimingProfile &ScanGroup::profile() const noexcept { return profile_; }
TimingProfile &ScanGroup::profile() noexcept { return profile_; }
const ScanMetrics &ScanGroup::metrics() const noexcept { return metrics_; }
ScanMetrics &ScanGroup::metrics() noexcept { return metrics_; }
const RttEstimator &ScanGroup::rtt() const noexcept { return rtt_; }
RttEstimator &ScanGroup::rtt() noexcept { return rtt_; }
const CongestionController &ScanGroup::congestion() const noexcept { return congestion_; }
CongestionController &ScanGroup::congestion() noexcept { return congestion_; }
std::size_t ScanGroup::queued_count() const noexcept { return queue_.size(); }

std::size_t ScanGroup::outstanding_count() const noexcept
{
    std::size_t count = 0U;
    for (const auto &entry : items_) {
        if (entry.second.state == ScanWorkState::Submitted) {
            ++count;
        }
    }
    return count;
}

std::size_t ScanGroup::total_count() const noexcept { return items_.size(); }

std::optional<ScanWorkState> ScanGroup::state(ScanWorkId id) const noexcept
{
    const auto iterator = items_.find(id);
    return iterator == items_.end() ? std::nullopt : std::optional<ScanWorkState>{iterator->second.state};
}

const char *scan_work_state_name(ScanWorkState state) noexcept
{
    switch (state) {
    case ScanWorkState::Queued:
        return "QUEUED";
    case ScanWorkState::Submitted:
        return "SUBMITTED";
    case ScanWorkState::Completed:
        return "COMPLETED";
    case ScanWorkState::TimedOut:
        return "TIMED_OUT";
    case ScanWorkState::Cancelled:
        return "CANCELLED";
    case ScanWorkState::Failed:
        return "FAILED";
    }
    return "FAILED";
}

} // namespace skan::scanengine
