#include "osdetect/os_scheduler.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <new>
#include <utility>

namespace skan::osdetect {
namespace {

constexpr std::array<OSProbeType, 8U> kProbeOrder{
    OSProbeType::TcpSynStandard,
    OSProbeType::TcpSynVariant,
    OSProbeType::TcpSynTimestamp,
    OSProbeType::TcpEcn,
    OSProbeType::TcpClosedStandard,
    OSProbeType::TcpClosedVariant,
    OSProbeType::IcmpEcho,
    OSProbeType::UdpPortUnreachable};

OSDetectionError error_for_status(core::StatusCode status) noexcept
{
    switch (status) {
    case core::StatusCode::InvalidArgument:
        return OSDetectionError::InvalidTarget;
    case core::StatusCode::PermissionDenied:
        return OSDetectionError::CapabilityUnavailable;
    case core::StatusCode::NotFound:
        return OSDetectionError::NoUsablePort;
    case core::StatusCode::ParseError:
        return OSDetectionError::MalformedResponse;
    case core::StatusCode::IoError:
        return OSDetectionError::TransportFailure;
    default:
        return OSDetectionError::InternalError;
    }
}

bool host_matches(const core::Host &host, const std::string &target) noexcept
{
    return target == host.address || (host.hostname.has_value() && target == *host.hostname);
}

} // namespace

OSScheduler::OSScheduler(
    io::IOEngine &engine,
    OSProbeTransport &transport,
    const db::OSFingerprintDatabase &database,
    OSSchedulerConfig config)
    : engine_(engine), transport_(transport), database_(database), config_(config), matcher_(database)
{
    if (config_.adaptive_timing) {
        timing_ = std::make_unique<scanengine::TimingController>(config_.timing_profile);
    }
}

OSScheduler::~OSScheduler()
{
    cancel_all();
}

core::StatusCode OSScheduler::submit(
    const core::Target &target,
    const std::vector<portscan::PortResult> &port_results)
{
    if (submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    submitted_ = true;
    target_ = target.original_specification;
    if (target_.empty() && !target.resolved_hosts.empty()) {
        target_ = target.resolved_hosts.front().address;
    }
    if (engine_.initialization_status() != core::StatusCode::Ok) {
        status_ = engine_.initialization_status();
        emit_result(OSDetectionState::Failed, error_for_status(status_));
        return status_;
    }
    if (database_.status() != core::StatusCode::Ok) {
        status_ = database_.status();
        emit_result(OSDetectionState::Failed, error_for_status(status_));
        return status_;
    }
    if (config_.max_outstanding == 0U || config_.timeout.count() <= 0 || config_.probe_port == 0U ||
        config_.max_results == 0U || (timing_ != nullptr && timing_->validate() != core::StatusCode::Ok)) {
        status_ = core::StatusCode::InvalidArgument;
        emit_result(OSDetectionState::Failed, OSDetectionError::InvalidTarget);
        return status_;
    }
    try {
        for (const core::Host &host : target.resolved_hosts) {
            if (host.address.empty()) {
                continue;
            }
            std::optional<portscan::Port> selected_port;
            for (const portscan::PortResult &port_result : port_results) {
                if (host_matches(host, port_result.target) && port_result.state == portscan::PortState::Open &&
                    port_result.port.protocol == portscan::Protocol::Tcp && port_result.port.number != 0U) {
                    selected_port = port_result.port;
                    break;
                }
            }
            portscan::Port port;
            if (selected_port.has_value()) {
                port = *selected_port;
            } else {
                port.number = config_.probe_port;
                port.protocol = portscan::Protocol::Tcp;
            }
            for (const OSProbeType type : kProbeOrder) {
                queue_.push_back(WorkItem{host, port, type});
            }
        }
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
        queue_.clear();
        emit_result(OSDetectionState::Failed, OSDetectionError::InternalError);
        return status_;
    }
    if (queue_.empty()) {
        status_ = core::StatusCode::NotFound;
        emit_result(OSDetectionState::Unavailable, OSDetectionError::NoUsablePort);
        return status_;
    }
    pump();
    finish_terminal();
    return status_;
}

void OSScheduler::receive(const OSProbeResponse &response) noexcept
{
    const auto iterator = pending_.find(response.id);
    if (iterator == pending_.end() || completed_ids_.contains(response.id) || expired_ids_.contains(response.id)) {
        return;
    }
    Pending &pending = iterator->second;
    const std::unique_ptr<OSProbe> probe = make_os_probe(pending.work.type);
    if (probe == nullptr) {
        ++malformed_count_;
        append_terminal_status(pending.work.type, OSProbeStatus::Malformed);
        finish_probe(pending, OSProbeAssessment{core::StatusCode::InternalError, OSProbeDisposition::Malformed,
                                                ResponseBehavior::Malformed, std::nullopt, std::nullopt},
                     response.received_at);
        return;
    }
    const OSProbeAssessment assessment = probe->assess(response, pending.submission);
    if (assessment.disposition == OSProbeDisposition::Unrelated) {
        return;
    }
    if (assessment.disposition == OSProbeDisposition::Malformed) {
        ++malformed_count_;
    } else {
        ++response_count_;
        append_observation(assessment);
    }
    const OSProbeTimePoint received_at =
        response.received_at == OSProbeTimePoint{} ? OSProbeClock::now() : response.received_at;
    finish_probe(pending, assessment, received_at);
}

core::StatusCode OSScheduler::run() noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode run_status = engine_.run();
    if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
        status_ = run_status;
    }
    finish_terminal();
    return status_;
}

core::StatusCode OSScheduler::run_once(int timeout_ms) noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode run_status = engine_.run_once(timeout_ms);
    if (status_ == core::StatusCode::Ok && run_status != core::StatusCode::Ok) {
        status_ = run_status;
    }
    finish_terminal();
    return status_;
}

void OSScheduler::stop() noexcept
{
    cancel_all();
    queue_.clear();
    if (submitted_ && !result_.has_value()) {
        emit_result(OSDetectionState::Partial, OSDetectionError::None);
    }
    engine_.stop();
}

bool OSScheduler::complete() const noexcept
{
    return submitted_ && queue_.empty() && pending_.empty();
}

std::size_t OSScheduler::pending_count() const noexcept
{
    return pending_.size();
}

core::StatusCode OSScheduler::status() const noexcept
{
    return status_;
}

const std::optional<OSDetectionResult> &OSScheduler::result() const noexcept
{
    return result_;
}

const scanengine::TimingController *OSScheduler::timing_controller() const noexcept
{
    return timing_.get();
}

void OSScheduler::pump() noexcept
{
    const std::size_t limit = timing_ == nullptr ? config_.max_outstanding
                                                    : timing_->parallelism_limit(config_.max_outstanding);
    while (status_ == core::StatusCode::Ok && !queue_.empty() && pending_.size() < limit) {
        WorkItem work = std::move(queue_.front());
        queue_.pop_front();
        start_or_retry(std::move(work));
    }
    finish_terminal();
}

void OSScheduler::start_or_retry(WorkItem work) noexcept
{
    const std::unique_ptr<OSProbe> probe = make_os_probe(work.type);
    if (probe == nullptr) {
        ++unsupported_count_;
        append_terminal_status(work.type, OSProbeStatus::Unsupported);
        return;
    }
    if (!transport_.supports(work.type)) {
        ++unsupported_count_;
        append_terminal_status(work.type, OSProbeStatus::Unsupported);
        return;
    }
    OSProbeSubmission submission;
    const OSProbeId id = next_id_++;
    const core::StatusCode build_status = probe->build(
        id,
        work.host,
        OSProbeConfig{config_.timeout, work.port.number},
        submission);
    if (build_status != core::StatusCode::Ok) {
        ++malformed_count_;
        append_terminal_status(work.type, OSProbeStatus::Malformed);
        return;
    }
    ++generated_count_;
    append_terminal_status(work.type, OSProbeStatus::Generated);
    Pending pending;
    pending.work = std::move(work);
    pending.submission = std::move(submission);
    pending.sent_at = OSProbeClock::now();
    io::TimerId timer_id = 0U;
    try {
        const std::chrono::milliseconds timeout = timing_ == nullptr ? config_.timeout : timing_->timeout();
        timer_id = engine_.schedule(timeout, [this, id]() { on_timeout(id); });
        if (timer_id == 0U) {
            status_ = core::StatusCode::InternalError;
            ++malformed_count_;
            append_terminal_status(pending.work.type, OSProbeStatus::Malformed);
            return;
        }
        pending.timer_id = timer_id;
        const auto inserted = pending_.emplace(id, std::move(pending));
        if (!inserted.second) {
            (void)engine_.cancel(timer_id);
            status_ = core::StatusCode::InternalError;
            return;
        }
        inserted.first->second.submission.status = OSProbeStatus::Sent;
        const core::StatusCode submit_status = transport_.submit(
            inserted.first->second.submission,
            [this](const OSProbeResponse &response) { receive(response); });
        if (submit_status != core::StatusCode::Ok) {
            (void)engine_.cancel(timer_id);
            pending_.erase(inserted.first);
            status_ = submit_status;
        } else {
            ++sent_count_;
            if (timing_ != nullptr) {
                timing_->on_submitted(pending_.size());
            }
            append_terminal_status(inserted.first->second.work.type, OSProbeStatus::Sent);
        }
    } catch (const std::bad_alloc &) {
        (void)engine_.cancel(timer_id);
        (void)transport_.cancel(id);
        pending_.erase(id);
        status_ = core::StatusCode::MemoryError;
    }
}

void OSScheduler::on_timeout(OSProbeId id) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end()) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    expired_ids_.insert(id);
    ++timeout_count_;
    append_terminal_status(pending.work.type, OSProbeStatus::Timeout);
    if (timing_ != nullptr) {
        timing_->on_timeout();
        if (timing_->should_retry(pending.work.retry_count)) {
            ++pending.work.retry_count;
            try {
                queue_.push_front(std::move(pending.work));
                ++timing_->metrics().retry_count;
                timing_->metrics().set_parallelism(pending_.size(), pending_.size());
                pump();
                return;
            } catch (const std::bad_alloc &) {
                status_ = core::StatusCode::MemoryError;
            }
        }
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    pump();
}

void OSScheduler::finish_probe(
    Pending &pending,
    const OSProbeAssessment &assessment,
    OSProbeTimePoint received_at) noexcept
{
    (void)assessment;
    const OSProbeId id = pending.submission.id;
    const OSProbeTimePoint sent_at = pending.sent_at;
    const io::TimerId timer_id = pending.timer_id;
    (void)engine_.cancel(timer_id);
    (void)transport_.cancel(id);
    const double rtt_ms = std::max(0.0, std::chrono::duration<double, std::milli>(received_at - sent_at).count());
    rtt_sum_ms_ += rtt_ms;
    ++rtt_count_;
    if (timing_ != nullptr) {
        timing_->on_response(std::chrono::milliseconds{static_cast<long long>(rtt_ms)});
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    completed_ids_.insert(id);
    pending_.erase(id);
    pump();
}

void OSScheduler::finish_terminal() noexcept
{
    if (submitted_ && queue_.empty() && pending_.empty() && !result_.has_value()) {
        if (status_ != core::StatusCode::Ok) {
            emit_result(OSDetectionState::Failed, error_for_status(status_));
        } else if (response_count_ > 0U && timeout_count_ == 0U && malformed_count_ == 0U) {
            emit_result(OSDetectionState::Complete, OSDetectionError::None);
        } else if (response_count_ > 0U || timeout_count_ > 0U || malformed_count_ > 0U || unsupported_count_ > 0U) {
            emit_result(OSDetectionState::Partial, timeout_count_ > 0U ? OSDetectionError::Timeout
                                                                        : OSDetectionError::UnsupportedProbe);
        } else {
            emit_result(OSDetectionState::Unavailable, OSDetectionError::NoUsablePort);
        }
        engine_.stop();
    }
}

void OSScheduler::append_observation(const OSProbeAssessment &assessment)
{
    if (!observed_.has_value()) {
        observed_.emplace();
    }
    if (assessment.tcp_observation.has_value()) {
        osdetect::append_observation(*observed_, *assessment.tcp_observation);
    }
    if (assessment.icmp_observation.has_value()) {
        osdetect::append_observation(*observed_, *assessment.icmp_observation);
    }
}

void OSScheduler::append_terminal_status(OSProbeType type, OSProbeStatus status)
{
    (void)type;
    if (!observed_.has_value()) {
        observed_.emplace();
    }
    switch (status) {
    case OSProbeStatus::Generated:
        ++observed_->probes_generated;
        break;
    case OSProbeStatus::Sent:
        ++observed_->probes_sent;
        break;
    case OSProbeStatus::ResponseReceived:
        ++observed_->responses_received;
        break;
    case OSProbeStatus::Timeout:
        ++observed_->probes_timed_out;
        break;
    case OSProbeStatus::Unsupported:
        ++observed_->probes_unsupported;
        break;
    case OSProbeStatus::Malformed:
        ++observed_->probes_malformed;
        break;
    }
    observed_->timestamp = OSProbeClock::now();
}

void OSScheduler::emit_result(OSDetectionState state, OSDetectionError error) noexcept
{
    if (result_.has_value()) {
        return;
    }
    try {
        OSDetectionResult result;
        result.target = target_;
        result.state = state;
        result.error = error;
        result.timestamp = OSProbeClock::now();
        result.probes_generated = generated_count_;
        result.probes_sent = sent_count_;
        result.responses_received = response_count_;
        result.probes_timed_out = timeout_count_;
        result.probes_unsupported = unsupported_count_;
        result.probes_malformed = malformed_count_;
        if (rtt_count_ > 0U) {
            result.rtt_ms = rtt_sum_ms_ / static_cast<double>(rtt_count_);
        }
        if (observed_.has_value()) {
            result.observed = *observed_;
            result.matches = matcher_.match(result.observed, config_.max_results);
            if (!result.matches.empty() && result.matches.front().confidence > 0.0) {
                const OSMatchResult &top = result.matches.front();
                result.vendor = top.vendor;
                result.family = top.family;
                result.generation = top.generation;
                result.device_type = top.device_type;
                result.confidence = top.confidence;
                result.category = top.category;
            }
        }
        result_ = std::move(result);
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
    }
}

void OSScheduler::cancel_all() noexcept
{
    for (const auto &entry : pending_) {
        (void)engine_.cancel(entry.second.timer_id);
        (void)transport_.cancel(entry.first);
    }
    pending_.clear();
}

} // namespace skan::osdetect
