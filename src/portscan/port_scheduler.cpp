#include "portscan/port_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <new>

#include "portscan/tcp_connect.hpp"
#include "portscan/tcp_ack.hpp"
#include "portscan/tcp_syn.hpp"

namespace skan::portscan {
namespace {

bool valid_host_address(const core::Host &host) noexcept
{
    return host.ip_address.valid() || core::parse_ip_address(host.address).has_value();
}

bool result_less(const PortResult &left, const PortResult &right) noexcept
{
    if (left.target != right.target) {
        return left.target < right.target;
    }
    if (left.port.number != right.port.number) {
        return left.port.number < right.port.number;
    }
    return static_cast<unsigned int>(left.probe) < static_cast<unsigned int>(right.probe);
}

ScanReason submission_failure_reason(core::StatusCode status) noexcept
{
    switch (status) {
    case core::StatusCode::PermissionDenied:
        return ScanReason::CapabilityUnavailable;
    case core::StatusCode::InvalidArgument:
        return ScanReason::InvalidTarget;
    default:
        return ScanReason::InternalError;
    }
}

bool should_confirm_negative(
    ScanProbeType probe,
    PortState state,
    ScanReason reason) noexcept
{
    if (probe != ScanProbeType::TcpConnect) {
        return false;
    }
    return (state == PortState::Closed && reason == ScanReason::ConnectionRefused) ||
           (state == PortState::Filtered && reason == ScanReason::Timeout) ||
           (state == PortState::Unknown && reason == ScanReason::SocketError);
}

} // namespace

PortScanScheduler::PortScanScheduler(
    io::IOEngine &engine,
    PortScanTransport &transport,
    PortScanConfig config)
    : engine_(engine),
      transport_(transport),
      config_(config)
{
    if (config_.adaptive_timing) {
        timing_ = std::make_unique<scanengine::TimingController>(config_.timing_profile);
    }
    if (config_.method == ScanProbeType::TcpConnect) {
        probe_ = std::make_unique<TcpConnectProbe>();
    } else if (config_.method == ScanProbeType::TcpSyn) {
        probe_ = std::make_unique<TcpSynProbe>();
    } else if (config_.method == ScanProbeType::TcpAck) {
        probe_ = std::make_unique<TcpAckProbe>();
    }
}

PortScanScheduler::~PortScanScheduler()
{
    for (auto &entry : pending_) {
        (void)engine_.cancel(entry.second.timer_id);
        (void)transport_.cancel(entry.first);
    }
    for (const auto &entry : deferred_retries_) {
        (void)engine_.cancel(entry.second.timer_id);
    }
    pending_.clear();
    deferred_retries_.clear();
    queue_.clear();
}

core::StatusCode PortScanScheduler::validate_config() const noexcept
{
    if (engine_.initialization_status() != core::StatusCode::Ok) {
        return engine_.initialization_status();
    }
    if (!probe_ || !transport_.supports(config_.method) || config_.timeout.count() <= 0 ||
        config_.retry_delay.count() < 0 || config_.max_outstanding == 0U ||
        (timing_ != nullptr && timing_->validate() != core::StatusCode::Ok)) {
        return !probe_ || !transport_.supports(config_.method) ? core::StatusCode::PermissionDenied
                                                               : core::StatusCode::InvalidArgument;
    }
    return core::StatusCode::Ok;
}

core::StatusCode PortScanScheduler::submit(
    const core::Target &target,
    const std::vector<Port> &ports)
{
    if (submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode config_status = validate_config();
    if (config_status != core::StatusCode::Ok) {
        status_ = config_status;
        return status_;
    }
    if (ports.empty() || target.resolved_hosts.empty()) {
        status_ = core::StatusCode::InvalidArgument;
        return status_;
    }
    for (const Port &port : ports) {
        if (port.protocol != Protocol::Tcp || port.number == 0U) {
            status_ = core::StatusCode::InvalidArgument;
            return status_;
        }
    }

    submitted_ = true;
    try {
        for (const core::Host &host : target.resolved_hosts) {
            if (!valid_host_address(host)) {
                for (const Port &port : ports) {
                    append_terminal_result(
                        WorkItem{host, port},
                        config_.method,
                        PortState::Unknown,
                        ScanReason::InvalidTarget);
                }
                status_ = core::StatusCode::InvalidArgument;
                continue;
            }
            for (const Port &port : ports) {
                queue_.push_back(WorkItem{host, port});
            }
        }
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
        queue_.clear();
        return status_;
    }
    if (status_ == core::StatusCode::Ok) {
        pump();
    } else {
        queue_.clear();
    }
    stop_if_idle();
    return status_;
}

core::StatusCode PortScanScheduler::submit_default(const core::Target &target)
{
    const std::vector<Port> ports = default_tcp_ports();
    return submit(target, ports);
}

core::StatusCode PortScanScheduler::run() noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode run_status = engine_.run();
    if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
        status_ = run_status;
    }
    return status_;
}

core::StatusCode PortScanScheduler::run_once(int timeout_ms) noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode run_status = engine_.run_once(timeout_ms);
    if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
        status_ = run_status;
    }
    return status_;
}

const scanengine::TimingController *PortScanScheduler::timing_controller() const noexcept
{
    return timing_.get();
}

void PortScanScheduler::receive(const PortResponse &response) noexcept
{
    const auto iterator = pending_.find(response.id);
    if (iterator == pending_.end() || !probe_) {
        return;
    }
    PortState state = PortState::Unknown;
    ScanReason reason = ScanReason::InternalError;
    const core::StatusCode assessment = probe_->assess(
        response,
        iterator->second.submission,
        state,
        reason);
    if (assessment != core::StatusCode::Ok) {
        return;
    }
    const PortScanTimePoint completed_at = response.received_at == PortScanTimePoint{}
                                               ? PortScanClock::now()
                                               : response.received_at;
    complete_pending(response.id, state, reason, completed_at);
}

const std::vector<PortResult> &PortScanScheduler::results() const noexcept
{
    sort_results();
    return results_;
}

std::size_t PortScanScheduler::queued_count() const noexcept
{
    return queue_.size();
}

std::size_t PortScanScheduler::pending_count() const noexcept
{
    return pending_.size();
}

bool PortScanScheduler::complete() const noexcept
{
    return submitted_ && queue_.empty() && pending_.empty() && deferred_retries_.empty();
}

core::StatusCode PortScanScheduler::status() const noexcept
{
    return status_;
}

void PortScanScheduler::pump() noexcept
{
    const std::size_t limit = timing_ == nullptr ? config_.max_outstanding
                                                    : timing_->parallelism_limit(config_.max_outstanding);
    while (status_ == core::StatusCode::Ok && !queue_.empty() && pending_.size() < limit) {
        WorkItem work = std::move(queue_.front());
        queue_.pop_front();
        const PortProbeId id = next_id_++;
        PortSubmission submission;
        const core::StatusCode build_status = probe_->build(id, work.host, work.port, config_, submission);
        if (build_status != core::StatusCode::Ok) {
            append_terminal_result(
                work,
                config_.method,
                PortState::Unknown,
                build_status == core::StatusCode::InvalidArgument ? ScanReason::InvalidTarget
                                                                   : ScanReason::InternalError);
            continue;
        }

        Pending pending;
        pending.work = work;
        pending.submission = submission;
        pending.started_at = PortScanClock::now();
        io::TimerId timer_id = 0U;
        try {
            const std::chrono::milliseconds timeout = timing_ == nullptr ? config_.timeout : timing_->timeout();
            timer_id = engine_.schedule(timeout, [this, id]() { on_timeout(id); });
            if (timer_id == 0U) {
                append_terminal_result(work, config_.method, PortState::Unknown, ScanReason::InternalError);
                if (status_ == core::StatusCode::Ok) {
                    status_ = core::StatusCode::InternalError;
                }
                break;
            }
            pending.timer_id = timer_id;
            const auto inserted = pending_.emplace(id, std::move(pending));
            if (!inserted.second) {
                (void)engine_.cancel(timer_id);
                append_terminal_result(work, config_.method, PortState::Unknown, ScanReason::InternalError);
                status_ = core::StatusCode::InternalError;
                break;
            }
            const core::StatusCode submit_status = transport_.submit(
                inserted.first->second.submission,
                [this](const PortResponse &response) { receive(response); });
            if (submit_status == core::StatusCode::Ok && timing_ != nullptr) {
                timing_->on_submitted(pending_.size());
            }
            if (submit_status != core::StatusCode::Ok) {
                const io::TimerId inserted_timer_id = inserted.first->second.timer_id;
                (void)engine_.cancel(inserted_timer_id);
                pending_.erase(inserted.first);
                append_terminal_result(
                    work,
                    config_.method,
                    PortState::Unknown,
                    submission_failure_reason(submit_status));
                status_ = submit_status;
                break;
            }
        } catch (const std::bad_alloc &) {
            (void)transport_.cancel(id);
            (void)engine_.cancel(timer_id);
            pending_.erase(id);
            append_terminal_result(work, config_.method, PortState::Unknown, ScanReason::InternalError);
            status_ = core::StatusCode::MemoryError;
            break;
        }
    }
    stop_if_idle();
}

void PortScanScheduler::sort_results() const noexcept
{
    if (!results_sorted_) {
        std::sort(results_.begin(), results_.end(), result_less);
        results_sorted_ = true;
    }
}

void PortScanScheduler::append_terminal_result(
    const WorkItem &work,
    ScanProbeType probe,
    PortState state,
    ScanReason reason,
    std::optional<double> rtt_ms) noexcept
{
    try {
        PortResult result;
        result.target = work.host.address;
        result.port = work.port;
        result.state = state;
        result.probe = probe;
        result.reason = reason;
        result.rtt_ms = rtt_ms;
        result.timestamp = PortScanClock::now();
        result.retry_count = work.retry_count;
        results_.push_back(std::move(result));
        results_sorted_ = false;
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
    }
}

void PortScanScheduler::complete_pending(
    PortProbeId id,
    PortState state,
    ScanReason reason,
    PortScanTimePoint completed_at) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end()) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)engine_.cancel(pending.timer_id);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    double rtt_ms = std::chrono::duration<double, std::milli>(completed_at - pending.started_at).count();
    if (rtt_ms < 0.0) {
        rtt_ms = 0.0;
    }
    if (timing_ != nullptr) {
        timing_->on_response(std::chrono::milliseconds{static_cast<long long>(rtt_ms)});
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    finish_attempt(std::move(pending.work), state, reason, rtt_ms);
}

void PortScanScheduler::finish_attempt(
    WorkItem work,
    PortState state,
    ScanReason reason,
    std::optional<double> rtt_ms) noexcept
{
    const std::size_t max_retries =
        timing_ == nullptr ? config_.retries : timing_->profile().max_retries;
    if (should_confirm_negative(config_.method, state, reason)) {
        std::size_t matching_observations = 0U;
        if (state == PortState::Closed) {
            matching_observations = ++work.closed_observations;
        } else if (state == PortState::Filtered) {
            matching_observations = ++work.filtered_observations;
        } else {
            matching_observations = ++work.error_observations;
        }

        if (matching_observations < 2U && work.retry_count < max_retries && defer_retry(work)) {
            pump();
            return;
        }

        const std::size_t evidence_kinds =
            static_cast<std::size_t>(work.closed_observations > 0U) +
            static_cast<std::size_t>(work.filtered_observations > 0U) +
            static_cast<std::size_t>(work.error_observations > 0U);
        if (matching_observations < 2U && evidence_kinds > 1U) {
            append_terminal_result(
                work,
                config_.method,
                PortState::Unknown,
                ScanReason::ConflictingEvidence,
                rtt_ms);
            pump();
            return;
        }
    } else if ((reason == ScanReason::Timeout || reason == ScanReason::AckTimeout) &&
               work.retry_count < max_retries && defer_retry(work)) {
        pump();
        return;
    }

    append_terminal_result(work, config_.method, state, reason, rtt_ms);
    pump();
}

bool PortScanScheduler::defer_retry(WorkItem work) noexcept
{
    if (next_retry_id_ == 0U) {
        status_ = core::StatusCode::InternalError;
        return false;
    }
    const RetryId retry_id = next_retry_id_++;
    ++work.retry_count;
    const io::TimerId timer_id = engine_.schedule(
        config_.retry_delay,
        [this, retry_id]() { on_retry_ready(retry_id); });
    if (timer_id == 0U) {
        status_ = core::StatusCode::InternalError;
        return false;
    }
    try {
        const auto inserted = deferred_retries_.emplace(
            retry_id,
            DeferredRetry{std::move(work), timer_id});
        if (!inserted.second) {
            (void)engine_.cancel(timer_id);
            status_ = core::StatusCode::InternalError;
            return false;
        }
    } catch (const std::bad_alloc &) {
        (void)engine_.cancel(timer_id);
        status_ = core::StatusCode::MemoryError;
        return false;
    }
    if (timing_ != nullptr) {
        ++timing_->metrics().retry_count;
    }
    return true;
}

void PortScanScheduler::on_retry_ready(RetryId id) noexcept
{
    const auto iterator = deferred_retries_.find(id);
    if (iterator == deferred_retries_.end()) {
        return;
    }
    WorkItem work = std::move(iterator->second.work);
    deferred_retries_.erase(iterator);
    try {
        queue_.push_front(std::move(work));
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
    }
    pump();
}

void PortScanScheduler::on_timeout(PortProbeId id) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end() || !probe_) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    if (timing_ != nullptr) {
        timing_->on_timeout();
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    finish_attempt(
        std::move(pending.work),
        probe_->timeout_state(),
        probe_->timeout_reason());
}

void PortScanScheduler::stop_if_idle() noexcept
{
    if (submitted_ && queue_.empty() && pending_.empty() && deferred_retries_.empty()) {
        engine_.stop();
    }
}

} // namespace skan::portscan
