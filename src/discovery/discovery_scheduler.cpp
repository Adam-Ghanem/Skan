#include "discovery/discovery_scheduler.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace skan::discovery {
namespace {

DiscoveryReason reason_for_status(core::StatusCode status) noexcept
{
    switch (status) {
    case core::StatusCode::PermissionDenied:
        return DiscoveryReason::PermissionFailure;
    case core::StatusCode::IoError:
        return DiscoveryReason::SocketFailure;
    case core::StatusCode::InvalidArgument:
        return DiscoveryReason::InvalidTarget;
    default:
        return DiscoveryReason::InternalError;
    }
}

} // namespace

DiscoveryScheduler::DiscoveryScheduler(
    io::IOEngine &io_engine,
    AuthorizationGate authorization,
    DiscoveryConfig config,
    DiscoveryTransport &transport)
    : io_engine_(io_engine),
      authorization_(std::move(authorization)),
      config_(std::move(config)),
      transport_(transport)
{
    for (const ProbeType type : config_.probes) {
        switch (type) {
        case ProbeType::IcmpEcho:
            probes_.push_back(std::make_unique<IcmpDiscoveryProbe>());
            break;
        case ProbeType::Tcp:
            probes_.push_back(std::make_unique<TcpDiscoveryProbe>());
            break;
        case ProbeType::Arp:
            probes_.push_back(std::make_unique<ArpDiscoveryProbe>());
            break;
        default:
            break;
        }
    }
}

DiscoveryScheduler::~DiscoveryScheduler()
{
    cancel_all();
}

const DiscoveryProbe *DiscoveryScheduler::probe_for(ProbeType type) const noexcept
{
    for (const std::unique_ptr<DiscoveryProbe> &probe : probes_) {
        if (probe->type() == type) {
            return probe.get();
        }
    }
    return nullptr;
}

core::StatusCode DiscoveryScheduler::submit(const core::Target &target)
{
    if (target.resolved_hosts.empty() || probes_.empty() || config_.timeout.count() <= 0 ||
        config_.max_outstanding == 0U || !authorization_.configured()) {
        if (!authorization_.configured() && !target.resolved_hosts.empty()) {
            append_result(DiscoveryResult{
                target.resolved_hosts.front().address,
                HostState::Unknown,
                probes_.empty() ? ProbeType::IcmpEcho : probes_.front()->type(),
                false,
                std::nullopt,
                DiscoveryClock::now(),
                DiscoveryReason::UnauthorizedTarget});
            return core::StatusCode::PermissionDenied;
        }
        return core::StatusCode::InvalidArgument;
    }

    core::StatusCode first_error = core::StatusCode::Ok;
    for (const core::Host &host : target.resolved_hosts) {
        const core::StatusCode status = submit_host(target, host);
        if (status != core::StatusCode::Ok && first_error == core::StatusCode::Ok) {
            first_error = status;
        }
    }
    pump();
    return first_error;
}

core::StatusCode DiscoveryScheduler::submit_host(const core::Target &target, const core::Host &host)
{
    if (host.address.empty() || !parse_ipv4_address(host.address).has_value()) {
        append_result(DiscoveryResult{
            host.address,
            HostState::Unknown,
            probes_.empty() ? ProbeType::IcmpEcho : probes_.front()->type(),
            false,
            std::nullopt,
            DiscoveryClock::now(),
            DiscoveryReason::InvalidTarget});
        return core::StatusCode::InvalidArgument;
    }
    bool authorized = false;
    try {
        authorized = authorization_.configured() && authorization_.authorize(target, host);
    } catch (...) {
        return core::StatusCode::InternalError;
    }
    if (!authorized) {
        append_result(DiscoveryResult{
            host.address,
            HostState::Unknown,
            probes_.empty() ? ProbeType::IcmpEcho : probes_.front()->type(),
            false,
            std::nullopt,
            DiscoveryClock::now(),
            DiscoveryReason::UnauthorizedTarget});
        return core::StatusCode::PermissionDenied;
    }
    if (probes_.empty() || config_.timeout.count() <= 0 || config_.max_outstanding == 0U) {
        return core::StatusCode::InvalidArgument;
    }

    std::size_t requested = 0U;
    for (const ProbeType type : config_.probes) {
        if (probe_for(type) != nullptr) {
            ++requested;
        }
    }
    if (requested == 0U || pending_.size() + work_queue_.size() + requested > config_.max_outstanding) {
        return core::StatusCode::IoError;
    }

    for (const ProbeType type : config_.probes) {
        work_queue_.push_back(WorkItem{target, host, type});
    }
    pump();
    return core::StatusCode::Ok;
}

core::StatusCode DiscoveryScheduler::submit_one(
    const core::Target &target,
    const core::Host &host,
    ProbeType type)
{
    const DiscoveryProbe *probe = probe_for(type);
    if (probe == nullptr) {
        return core::StatusCode::InvalidArgument;
    }

    ProbeSubmission submission;
    const ProbeId id = next_probe_id_;
    ++next_probe_id_;
    if (next_probe_id_ == 0U) {
        next_probe_id_ = 1U;
    }
    try {
        const core::StatusCode build_status = probe->build(id, host, config_, submission);
        if (build_status != core::StatusCode::Ok) {
            append_result(DiscoveryResult{
                host.address, HostState::Unknown, type, false, std::nullopt,
                DiscoveryClock::now(), reason_for_status(build_status)});
            return build_status;
        }
        const core::StatusCode transport_status = transport_.submit(submission);
        if (transport_status != core::StatusCode::Ok) {
            append_result(DiscoveryResult{
                host.address, HostState::Unknown, type, false, std::nullopt,
                DiscoveryClock::now(), reason_for_status(transport_status)});
            return transport_status;
        }

        PendingProbe pending;
        pending.id = id;
        pending.type = type;
        pending.target = target.original_specification;
        pending.probe = probe;
        pending.submission = std::move(submission);
        pending.sent_at = DiscoveryClock::now();
        pending.deadline = pending.sent_at + config_.timeout;
        pending.timer_id = io_engine_.schedule(config_.timeout, [this, id] {
            expire(id);
        });
        if (pending.timer_id == 0U) {
            append_result(DiscoveryResult{
                host.address, HostState::Unknown, type, false, std::nullopt,
                DiscoveryClock::now(), DiscoveryReason::InternalError});
            return core::StatusCode::InternalError;
        }
        pending_.emplace(id, std::move(pending));
        return core::StatusCode::Ok;
    } catch (...) {
        append_result(DiscoveryResult{
            host.address, HostState::Unknown, type, false, std::nullopt,
            DiscoveryClock::now(), DiscoveryReason::InternalError});
        return core::StatusCode::InternalError;
    }
}

void DiscoveryScheduler::pump() noexcept
{
    while (!work_queue_.empty() && pending_.size() < config_.max_outstanding) {
        WorkItem item = std::move(work_queue_.front());
        work_queue_.pop_front();
        const core::StatusCode status = submit_one(item.target, item.host, item.type);
        if (status != core::StatusCode::Ok) {
            continue;
        }
    }
}

core::StatusCode DiscoveryScheduler::receive(const DiscoveryResponse &response)
{
    if (response.probe_id == 0U) {
        return core::StatusCode::InvalidArgument;
    }
    const auto pending_it = pending_.find(response.probe_id);
    if (pending_it == pending_.end()) {
        if (expired_probe_ids_.contains(response.probe_id)) {
            ++late_response_count_;
            return core::StatusCode::NotFound;
        }
        if (completed_probe_ids_.contains(response.probe_id)) {
            ++duplicate_response_count_;
            return core::StatusCode::Ok;
        }
        return core::StatusCode::NotFound;
    }

    PendingProbe &pending = pending_it->second;
    const ResponseDisposition disposition = pending.probe->assess(response, pending.submission);
    if (disposition == ResponseDisposition::Malformed) {
        append_result(DiscoveryResult{
            pending.submission.target,
            HostState::Unknown,
            pending.type,
            false,
            std::nullopt,
            DiscoveryClock::now(),
            DiscoveryReason::MalformedResponse});
        (void)io_engine_.cancel(pending.timer_id);
        completed_probe_ids_.insert(pending.id);
        pending_.erase(pending_it);
        pump();
        if (complete()) {
            io_engine_.stop();
        }
        return core::StatusCode::ParseError;
    }
    if (disposition == ResponseDisposition::Unrelated) {
        return core::StatusCode::Ok;
    }

    const DiscoveryTimePoint received_at = response.received_at == DiscoveryTimePoint{}
        ? DiscoveryClock::now() : response.received_at;
    const std::chrono::duration<double, std::milli> elapsed = received_at - pending.sent_at;
    const double rtt_ms = std::max(0.0, elapsed.count());
    const DiscoveryReason reason = pending.probe->positive_reason(response);
    append_result(DiscoveryResult{
        pending.submission.target,
        HostState::Up,
        pending.type,
        true,
        rtt_ms,
        received_at,
        reason});
    (void)io_engine_.cancel(pending.timer_id);
    completed_probe_ids_.insert(pending.id);
    pending_.erase(pending_it);
    pump();
    if (complete()) {
        io_engine_.stop();
    }
    return core::StatusCode::Ok;
}

void DiscoveryScheduler::expire(ProbeId id) noexcept
{
    const auto pending_it = pending_.find(id);
    if (pending_it == pending_.end()) {
        return;
    }
    const PendingProbe &pending = pending_it->second;
    append_result(DiscoveryResult{
        pending.submission.target,
        HostState::Unknown,
        pending.type,
        false,
        std::nullopt,
        DiscoveryClock::now(),
        DiscoveryReason::Timeout});
    expired_probe_ids_.insert(id);
    pending_.erase(pending_it);
    pump();
    if (complete()) {
        io_engine_.stop();
    }
}

void DiscoveryScheduler::append_result(DiscoveryResult result)
{
    if (result.timestamp == DiscoveryTimePoint{}) {
        result.timestamp = DiscoveryClock::now();
    }
    evidence_[result.target].push_back(result);
    results_.push_back(std::move(result));
}

core::StatusCode DiscoveryScheduler::run_once(int timeout_ms)
{
    pump();
    const core::StatusCode status = io_engine_.run_once(timeout_ms);
    pump();
    return status;
}

core::StatusCode DiscoveryScheduler::run()
{
    pump();
    return io_engine_.run();
}

void DiscoveryScheduler::stop() noexcept
{
    io_engine_.stop();
}

void DiscoveryScheduler::cancel_all() noexcept
{
    for (const auto &entry : pending_) {
        (void)io_engine_.cancel(entry.second.timer_id);
    }
    pending_.clear();
    work_queue_.clear();
}

bool DiscoveryScheduler::complete() const noexcept
{
    return pending_.empty() && work_queue_.empty();
}

std::size_t DiscoveryScheduler::pending_count() const noexcept
{
    return pending_.size() + work_queue_.size();
}

std::size_t DiscoveryScheduler::duplicate_response_count() const noexcept
{
    return duplicate_response_count_;
}

std::size_t DiscoveryScheduler::late_response_count() const noexcept
{
    return late_response_count_;
}

HostState DiscoveryScheduler::host_state(const std::string &address) const noexcept
{
    const auto evidence_it = evidence_.find(address);
    if (evidence_it == evidence_.end()) {
        return HostState::Unknown;
    }
    bool has_down = false;
    for (const DiscoveryResult &result : evidence_it->second) {
        if (result.state == HostState::Up) {
            return HostState::Up;
        }
        has_down = has_down || result.state == HostState::Down;
    }
    return has_down ? HostState::Down : HostState::Unknown;
}

std::vector<DiscoveryResult> DiscoveryScheduler::results() const
{
    return results_;
}

} // namespace skan::discovery
