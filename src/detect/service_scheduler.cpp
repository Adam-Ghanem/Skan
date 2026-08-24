#include "detect/service_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <new>
#include <utility>

namespace skan::detect {
namespace {

DetectionError error_for_status(core::StatusCode status) noexcept
{
    switch (status) {
    case core::StatusCode::PermissionDenied:
        return DetectionError::TransportFailure;
    case core::StatusCode::InvalidArgument:
        return DetectionError::InvalidTarget;
    case core::StatusCode::IoError:
        return DetectionError::TransportFailure;
    case core::StatusCode::ParseError:
        return DetectionError::MalformedResponse;
    default:
        return DetectionError::InternalError;
    }
}

bool already_seen(
    const std::vector<std::pair<std::string, std::uint16_t>> &seen,
    const std::string &target,
    std::uint16_t port) noexcept
{
    return std::any_of(seen.begin(), seen.end(), [&target, port](const auto &entry) {
        return entry.first == target && entry.second == port;
    });
}

} // namespace

ServiceScheduler::ServiceScheduler(
    io::IOEngine &engine,
    ServiceTransport &transport,
    const ServiceProbeDatabase &database,
    ServiceDetectionConfig config)
    : engine_(engine),
      transport_(transport),
      database_(database),
      config_(config),
      matcher_(database)
{
}

ServiceScheduler::~ServiceScheduler()
{
    for (auto &entry : pending_) {
        (void)engine_.cancel(entry.second.timer_id);
        (void)transport_.cancel(entry.first);
    }
    pending_.clear();
    queue_.clear();
}

core::StatusCode ServiceScheduler::validate_config() const noexcept
{
    if (engine_.initialization_status() != core::StatusCode::Ok) {
        return engine_.initialization_status();
    }
    if (database_.status() != core::StatusCode::Ok) {
        return database_.status();
    }
    if (config_.max_outstanding == 0U || config_.timeout.count() <= 0 ||
        config_.max_response_bytes == 0U || config_.max_probes_per_port == 0U) {
        return core::StatusCode::InvalidArgument;
    }
    return core::StatusCode::Ok;
}

core::StatusCode ServiceScheduler::submit(const std::vector<portscan::PortResult> &open_ports)
{
    if (submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode configuration_status = validate_config();
    if (configuration_status != core::StatusCode::Ok) {
        status_ = configuration_status;
        return status_;
    }
    submitted_ = true;
    std::vector<std::pair<std::string, std::uint16_t>> seen;
    try {
        for (const portscan::PortResult &port_result : open_ports) {
            if (port_result.state != portscan::PortState::Open ||
                port_result.port.protocol != portscan::Protocol::Tcp) {
                continue;
            }
            if (port_result.target.empty() || port_result.port.number == 0U) {
                append_result(
                    port_result,
                    nullptr,
                    DetectionState::InvalidTarget,
                    DetectionError::InvalidTarget,
                    nullptr);
                status_ = core::StatusCode::InvalidArgument;
                continue;
            }
            if (already_seen(seen, port_result.target, port_result.port.number)) {
                continue;
            }
            seen.emplace_back(port_result.target, port_result.port.number);
            WorkItem work;
            work.port_result = port_result;
            work.probe_indices = database_.ordered_probe_indices(
                port_result.port,
                config_.max_probes_per_port);
            if (work.probe_indices.empty()) {
                append_result(
                    port_result,
                    nullptr,
                    DetectionState::Unknown,
                    DetectionError::UnsupportedProtocol,
                    nullptr);
                continue;
            }
            queue_.push_back(std::move(work));
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

core::StatusCode ServiceScheduler::run() noexcept
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

core::StatusCode ServiceScheduler::run_once(int timeout_ms) noexcept
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

void ServiceScheduler::receive(const ServiceResponse &response) noexcept
{
    const auto iterator = pending_.find(response.id);
    if (iterator == pending_.end()) {
        return;
    }
    Pending &pending = iterator->second;
    const std::size_t active_probe_index = pending.probe_index;
    const ServiceProbeDefinition &definition = database_.probes()[active_probe_index];
    const ServiceProbe probe(definition, config_.max_response_bytes);
    std::string chunk;
    DetectionError assessment_error = DetectionError::None;
    const core::StatusCode assessment = probe.assess(
        response,
        pending.submission,
        chunk,
        assessment_error);
    if (assessment == core::StatusCode::NotFound) {
        if (response.kind != ServiceResponseKind::Closed) {
            return;
        }
    } else if (assessment == core::StatusCode::MemoryError &&
               assessment_error == DetectionError::ResponseTooLarge) {
        complete_pending(
            response.id,
            DetectionState::ResponseTooLarge,
            DetectionError::ResponseTooLarge,
            nullptr,
            response.received_at == DetectionTimePoint{} ? DetectionClock::now() : response.received_at);
        return;
    } else if (assessment != core::StatusCode::Ok && response.kind != ServiceResponseKind::Closed) {
        complete_pending(
            response.id,
            DetectionState::Error,
            assessment_error == DetectionError::None ? error_for_status(assessment) : assessment_error,
            nullptr,
            response.received_at == DetectionTimePoint{} ? DetectionClock::now() : response.received_at);
        return;
    }

    if (assessment == core::StatusCode::Ok && !chunk.empty()) {
        try {
            pending.response += chunk;
        } catch (const std::bad_alloc &) {
            status_ = core::StatusCode::MemoryError;
            complete_pending(
                response.id,
                DetectionState::Error,
                DetectionError::InternalError,
                nullptr,
                DetectionClock::now());
            return;
        }
    }

    ServiceMatchResult match;
    try {
        match = matcher_.match(definition, pending.response);
    } catch (...) {
        complete_pending(
            response.id,
            DetectionState::Error,
            DetectionError::InternalError,
            nullptr,
            DetectionClock::now());
        return;
    }
    if (match.matched) {
        complete_pending(
            response.id,
            DetectionState::Detected,
            DetectionError::None,
            &match,
            response.received_at == DetectionTimePoint{} ? DetectionClock::now() : response.received_at);
        return;
    }
    if (response.kind != ServiceResponseKind::Closed) {
        return;
    }

    Pending finished = std::move(iterator->second);
    (void)engine_.cancel(finished.timer_id);
    (void)transport_.cancel(response.id);
    pending_.erase(iterator);
    if (finished.work.next_probe + 1U < finished.work.probe_indices.size()) {
        ++finished.work.next_probe;
        try {
            queue_.push_front(std::move(finished.work));
        } catch (const std::bad_alloc &) {
            status_ = core::StatusCode::MemoryError;
        }
        pump();
        return;
    }
    const DetectionTimePoint completed_at =
        response.received_at == DetectionTimePoint{} ? DetectionClock::now() : response.received_at;
    double rtt_ms = std::chrono::duration<double, std::milli>(completed_at - finished.started_at).count();
    if (rtt_ms < 0.0) {
        rtt_ms = 0.0;
    }
    append_result(
        finished.work.port_result,
        &database_.probes()[active_probe_index],
        DetectionState::Unknown,
        finished.response.empty() ? DetectionError::ConnectionClosed : DetectionError::NoMatch,
        nullptr,
        rtt_ms);
    pump();
}

const std::vector<ServiceResult> &ServiceScheduler::results() const noexcept
{
    return results_;
}

std::size_t ServiceScheduler::pending_count() const noexcept
{
    return pending_.size();
}

std::size_t ServiceScheduler::queued_count() const noexcept
{
    return queue_.size();
}

bool ServiceScheduler::complete() const noexcept
{
    return submitted_ && queue_.empty() && pending_.empty();
}

core::StatusCode ServiceScheduler::status() const noexcept
{
    return status_;
}

void ServiceScheduler::pump() noexcept
{
    while (status_ == core::StatusCode::Ok && !queue_.empty() &&
           pending_.size() < config_.max_outstanding) {
        WorkItem work = std::move(queue_.front());
        queue_.pop_front();
        start_or_retry(std::move(work));
    }
    stop_if_idle();
}

void ServiceScheduler::start_or_retry(WorkItem work) noexcept
{
    if (work.next_probe >= work.probe_indices.size()) {
        append_result(
            work.port_result,
            nullptr,
            DetectionState::Unknown,
            DetectionError::NoMatch,
            nullptr);
        return;
    }
    const std::size_t probe_index = work.probe_indices[work.next_probe];
    const ServiceProbeDefinition &definition = database_.probes()[probe_index];
    const ServiceProbe probe(definition, config_.max_response_bytes);
    ServiceSubmission submission;
    const ServiceProbeId id = next_id_++;
    const core::StatusCode build_status = probe.build(
        id,
        core::Host{work.port_result.target, std::nullopt, true},
        work.port_result.port,
        submission);
    if (build_status != core::StatusCode::Ok) {
        append_result(
            work.port_result,
            &definition,
            DetectionState::Error,
            error_for_status(build_status),
            nullptr);
        return;
    }

    Pending pending;
    pending.work = work;
    pending.submission = submission;
    pending.probe_index = probe_index;
    pending.started_at = DetectionClock::now();
    io::TimerId timer_id = 0U;
    try {
        timer_id = engine_.schedule(config_.timeout, [this, id]() { on_timeout(id); });
        pending.timer_id = timer_id;
        const auto inserted = pending_.emplace(id, std::move(pending));
        if (!inserted.second) {
            (void)engine_.cancel(timer_id);
            status_ = core::StatusCode::InternalError;
            append_result(work.port_result, &definition, DetectionState::Error,
                          DetectionError::InternalError, nullptr);
            return;
        }
        const core::StatusCode submit_status = transport_.submit(
            inserted.first->second.submission,
            [this](const ServiceResponse &response) { receive(response); });
        if (submit_status != core::StatusCode::Ok) {
            const io::TimerId inserted_timer_id = inserted.first->second.timer_id;
            (void)engine_.cancel(inserted_timer_id);
            pending_.erase(inserted.first);
            status_ = submit_status;
            append_result(
                work.port_result,
                &definition,
                DetectionState::Error,
                error_for_status(submit_status),
                nullptr);
        }
    } catch (const std::bad_alloc &) {
        (void)transport_.cancel(id);
        (void)engine_.cancel(timer_id);
        pending_.erase(id);
        status_ = core::StatusCode::MemoryError;
        append_result(
            work.port_result,
            &definition,
            DetectionState::Error,
            DetectionError::InternalError,
            nullptr);
    }
}

void ServiceScheduler::complete_pending(
    ServiceProbeId id,
    DetectionState state,
    DetectionError error,
    const ServiceMatchResult *match,
    DetectionTimePoint completed_at) noexcept
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
    append_result(
        pending.work.port_result,
        &database_.probes()[pending.probe_index],
        state,
        error,
        match,
        rtt_ms);
    pump();
}

void ServiceScheduler::on_timeout(ServiceProbeId id) noexcept
{
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end()) {
        return;
    }
    Pending pending = std::move(iterator->second);
    (void)transport_.cancel(id);
    pending_.erase(iterator);
    append_result(
        pending.work.port_result,
        &database_.probes()[pending.probe_index],
        DetectionState::Timeout,
        DetectionError::Timeout,
        nullptr);
    pump();
}

void ServiceScheduler::append_result(
    const portscan::PortResult &port_result,
    const ServiceProbeDefinition *probe,
    DetectionState state,
    DetectionError error,
    const ServiceMatchResult *match,
    std::optional<double> rtt_ms) noexcept
{
    try {
        ServiceResult result;
        result.target = port_result.target;
        result.port = port_result.port;
        result.protocol = port_result.port.protocol;
        result.port_state = port_result.state;
        result.state = state;
        result.method = probe == nullptr
                            ? DetectionMethod::Unknown
                            : (probe->name.find("Banner") != std::string::npos ? DetectionMethod::Banner
                                                                                 : DetectionMethod::Probe);
        if (probe != nullptr) {
            result.probe_name = probe->name;
        }
        result.error = error;
        result.rtt_ms = rtt_ms;
        result.timestamp = DetectionClock::now();
        if (match != nullptr) {
            result.service = match->service;
            result.product = match->product;
            result.version = match->version;
            result.extra = match->extra;
            result.confidence = match->confidence;
        }
        results_.push_back(std::move(result));
        std::sort(results_.begin(), results_.end(), service_result_less);
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
    }
}

void ServiceScheduler::stop_if_idle() noexcept
{
    if (submitted_ && queue_.empty() && pending_.empty()) {
        engine_.stop();
    }
}

} // namespace skan::detect
