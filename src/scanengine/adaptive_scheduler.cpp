#include "scanengine/adaptive_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <new>
#include <utility>

namespace skan::scanengine {

core::StatusCode RecordingScanTransport::submit(const ScanWorkItem &work, ScanCompletionCallback callback)
{
    if (work.id == 0U || !callback) {
        return core::StatusCode::InvalidArgument;
    }
    try {
        submissions_.push_back(work);
        callbacks_[work.id] = std::move(callback);
    } catch (const std::bad_alloc &) {
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode RecordingScanTransport::cancel(ScanWorkId id) noexcept
{
    callbacks_.erase(id);
    return core::StatusCode::Ok;
}

void RecordingScanTransport::deliver(const ScanCompletion &completion)
{
    const auto iterator = callbacks_.find(completion.id);
    if (iterator == callbacks_.end()) {
        return;
    }
    ScanCompletionCallback callback = iterator->second;
    if (completion.state == ScanCompletionState::ValidResponse ||
        completion.state == ScanCompletionState::MalformedResponse ||
        completion.state == ScanCompletionState::Failed || completion.state == ScanCompletionState::Timeout) {
        callbacks_.erase(iterator);
    }
    callback(completion);
}

const std::vector<ScanWorkItem> &RecordingScanTransport::submissions() const noexcept
{
    return submissions_;
}

std::size_t RecordingScanTransport::active_callback_count() const noexcept
{
    return callbacks_.size();
}

AdaptiveScheduler::AdaptiveScheduler(io::IOEngine &engine, ScanTransport &transport, ScanGroup &group)
    : engine_(engine), transport_(transport), group_(group)
{
}

AdaptiveScheduler::~AdaptiveScheduler()
{
    shutdown();
}

core::StatusCode AdaptiveScheduler::start() noexcept
{
    if (started_) {
        return core::StatusCode::InvalidArgument;
    }
    if (engine_.initialization_status() != core::StatusCode::Ok) {
        status_ = engine_.initialization_status();
        return status_;
    }
    if (group_.validate() != core::StatusCode::Ok) {
        status_ = core::StatusCode::InvalidArgument;
        return status_;
    }
    started_ = true;
    group_.metrics().started_at = ScanClock::now();
    pump();
    finish_if_idle();
    return status_;
}

core::StatusCode AdaptiveScheduler::run() noexcept
{
    if (!started_) {
        const core::StatusCode start_status = start();
        if (start_status != core::StatusCode::Ok) {
            return start_status;
        }
    }
    if (status_ == core::StatusCode::Ok && !stopped_) {
        const core::StatusCode run_status = engine_.run();
        if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
            status_ = run_status;
        }
    }
    return status_;
}

core::StatusCode AdaptiveScheduler::run_once(int timeout_ms) noexcept
{
    if (!started_) {
        const core::StatusCode start_status = start();
        if (start_status != core::StatusCode::Ok) {
            return start_status;
        }
    }
    if (status_ == core::StatusCode::Ok && !stopped_) {
        const core::StatusCode run_status = engine_.run_once(timeout_ms);
        if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
            status_ = run_status;
        }
    }
    return status_;
}

void AdaptiveScheduler::receive(const ScanCompletion &completion) noexcept
{
    if (stopped_) {
        return;
    }
    const auto iterator = pending_.find(completion.id);
    if (iterator == pending_.end()) {
        if (completed_ids_.find(completion.id) != completed_ids_.end()) {
            ++group_.metrics().duplicate_responses;
        } else if (expired_ids_.find(completion.id) != expired_ids_.end()) {
            ++group_.metrics().late_responses;
        }
        return;
    }
    switch (completion.state) {
    case ScanCompletionState::ValidResponse:
        complete_pending(completion);
        break;
    case ScanCompletionState::Timeout:
        on_timeout(completion.id);
        break;
    case ScanCompletionState::MalformedResponse:
        ++group_.metrics().malformed_responses;
        fail_pending(completion.id, true);
        break;
    case ScanCompletionState::Failed:
        fail_pending(completion.id, false);
        break;
    case ScanCompletionState::Duplicate:
        ++group_.metrics().duplicate_responses;
        break;
    case ScanCompletionState::LateResponse:
        ++group_.metrics().late_responses;
        break;
    }
}

core::StatusCode AdaptiveScheduler::cancel(ScanWorkId id) noexcept
{
    if (!started_ || stopped_) {
        return core::StatusCode::InvalidArgument;
    }
    const auto iterator = pending_.find(id);
    if (iterator != pending_.end()) {
        const io::TimerId timer_id = iterator->second.timer_id;
        (void)engine_.cancel(timer_id);
        (void)transport_.cancel(id);
        pending_.erase(iterator);
        expired_ids_.insert(id);
        (void)group_.cancel(id);
    } else if (!group_.cancel(id)) {
        return core::StatusCode::NotFound;
    }
    pump();
    finish_if_idle();
    return core::StatusCode::Ok;
}

void AdaptiveScheduler::shutdown() noexcept
{
    if (stopped_) {
        return;
    }
    stopped_ = true;
    for (const auto &entry : pending_) {
        (void)engine_.cancel(entry.second.timer_id);
        (void)transport_.cancel(entry.first);
        expired_ids_.insert(entry.first);
    }
    pending_.clear();
    group_.cancel_all();
    group_.metrics().completed_at = ScanClock::now();
    engine_.stop();
}

bool AdaptiveScheduler::complete() const noexcept
{
    return started_ && group_.queued_count() == 0U && pending_.empty();
}

std::size_t AdaptiveScheduler::pending_count() const noexcept
{
    return pending_.size();
}

core::StatusCode AdaptiveScheduler::status() const noexcept
{
    return status_;
}

void AdaptiveScheduler::pump() noexcept
{
    while (status_ == core::StatusCode::Ok && !stopped_ && group_.queued_count() > 0U &&
           pending_.size() < group_.congestion().state().current_parallelism) {
        std::optional<ScanWorkItem> next;
        try {
            next = group_.next_queued();
        } catch (const std::bad_alloc &) {
            status_ = core::StatusCode::MemoryError;
            break;
        }
        if (!next.has_value()) {
            break;
        }
        ScanWorkItem work = std::move(*next);
        const ScanTimePoint sent_at = ScanClock::now();
        const ScanTimePoint deadline = sent_at + group_.rtt().timeout();
        if (!group_.mark_submitted(work.id, sent_at, deadline)) {
            status_ = core::StatusCode::InternalError;
            break;
        }
        work.state = ScanWorkState::Submitted;
        work.submitted_at = sent_at;
        work.deadline = deadline;
        Pending pending;
        pending.work = work;
        pending.sent_at = sent_at;
        io::TimerId timer_id = 0U;
        try {
            timer_id = engine_.schedule(
                group_.rtt().timeout(),
                [this, id = work.id]() { on_timeout(id); });
            if (timer_id == 0U) {
                (void)group_.mark_failed(work.id);
                status_ = core::StatusCode::InternalError;
                break;
            }
            pending.timer_id = timer_id;
            const auto inserted = pending_.emplace(work.id, std::move(pending));
            if (!inserted.second) {
                (void)engine_.cancel(timer_id);
                (void)group_.mark_failed(work.id);
                status_ = core::StatusCode::InternalError;
                break;
            }
            const core::StatusCode submit_status = transport_.submit(
                work,
                [this](const ScanCompletion &completion) { receive(completion); });
            if (submit_status != core::StatusCode::Ok) {
                (void)engine_.cancel(timer_id);
                pending_.erase(work.id);
                (void)group_.mark_failed(work.id);
                status_ = submit_status;
                break;
            }
            group_.metrics().set_parallelism(
                pending_.size(),
                std::max(group_.metrics().maximum_observed_parallelism, pending_.size()));
        } catch (const std::bad_alloc &) {
            (void)engine_.cancel(timer_id);
            (void)transport_.cancel(work.id);
            pending_.erase(work.id);
            (void)group_.mark_failed(work.id);
            status_ = core::StatusCode::MemoryError;
            break;
        }
    }
    finish_if_idle();
}

void AdaptiveScheduler::on_timeout(ScanWorkId id) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end() || stopped_) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    expired_ids_.insert(id);
    (void)group_.mark_timed_out(id);
    group_.congestion().on_timeout();
    group_.metrics().estimated_drop_rate = group_.congestion().state().drop_rate;
    if (!group_.requeue_for_retry(std::move(pending.work))) {
        update_adaptive_state();
    }
    pump();
}

void AdaptiveScheduler::complete_pending(const ScanCompletion &completion) noexcept
{
    const auto iterator = pending_.find(completion.id);
    if (iterator == pending_.end()) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)engine_.cancel(pending.timer_id);
    (void)transport_.cancel(completion.id);
    pending_.erase(iterator);
    const ScanTimePoint received_at = ScanClock::now();
    std::chrono::milliseconds sample{0};
    if (completion.rtt.has_value()) {
        sample = *completion.rtt;
    } else if (received_at > pending.sent_at) {
        sample = std::chrono::duration_cast<std::chrono::milliseconds>(received_at - pending.sent_at);
    }
    (void)group_.mark_completed(completion.id);
    group_.congestion().on_response();
    group_.metrics().estimated_drop_rate = group_.congestion().state().drop_rate;
    group_.metrics().record_rtt(sample);
    (void)group_.rtt().observe(sample, RttSampleValidity::ValidResponse);
    completed_ids_.insert(completion.id);
    update_adaptive_state();
    pump();
}

void AdaptiveScheduler::fail_pending(ScanWorkId id, bool malformed) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end()) {
        return;
    }
    const io::TimerId timer_id = iterator->second.timer_id;
    (void)engine_.cancel(timer_id);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    completed_ids_.insert(id);
    (void)group_.mark_failed(id);
    (void)malformed;
    update_adaptive_state();
    pump();
}

void AdaptiveScheduler::finish_if_idle() noexcept
{
    if (started_ && !stopped_ && group_.queued_count() == 0U && pending_.empty()) {
        group_.metrics().completed_at = ScanClock::now();
        engine_.stop();
    }
}

void AdaptiveScheduler::update_adaptive_state() noexcept
{
    group_.metrics().current_parallelism = group_.congestion().state().current_parallelism;
    group_.metrics().estimated_drop_rate = group_.congestion().state().drop_rate;
}

} // namespace skan::scanengine
