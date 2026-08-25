#include "orchestrator/scan_session.hpp"

#include <utility>

namespace skan::orchestrator {

const char *pipeline_state_name(PipelineState state) noexcept
{
    switch (state) {
    case PipelineState::Created:
        return "created";
    case PipelineState::Initializing:
        return "initializing";
    case PipelineState::Discovering:
        return "discovering";
    case PipelineState::PortScanning:
        return "port-scanning";
    case PipelineState::DetectingServices:
        return "detecting-services";
    case PipelineState::DetectingOS:
        return "detecting-os";
    case PipelineState::Serializing:
        return "serializing";
    case PipelineState::Completed:
        return "completed";
    case PipelineState::Cancelled:
        return "cancelled";
    case PipelineState::Failed:
        return "failed";
    }
    return "unknown";
}

ScanSession::ScanSession(std::string session_id, ScanEventSink sink)
    : id_(std::move(session_id)),
      io_engine_(std::make_unique<io::IOEngine>()),
      sink_(std::move(sink)),
      started_at_(std::chrono::steady_clock::now()),
      finished_at_(started_at_)
{
}

ScanSession::~ScanSession()
{
    cancel_callback_ = {};
    if (io_engine_ != nullptr) {
        io_engine_->stop();
    }
}

const std::string &ScanSession::id() const noexcept { return id_; }
io::IOEngine &ScanSession::io_engine() noexcept { return *io_engine_; }
const io::IOEngine &ScanSession::io_engine() const noexcept { return *io_engine_; }
PipelineState ScanSession::state() const noexcept { return state_; }
bool ScanSession::cancelled() const noexcept { return cancel_requested_ || state_ == PipelineState::Cancelled; }
bool ScanSession::terminal() const noexcept
{
    return state_ == PipelineState::Completed || state_ == PipelineState::Cancelled ||
           state_ == PipelineState::Failed;
}

core::StatusCode ScanSession::transition(PipelineState next) noexcept
{
    if (state_ == next) {
        return core::StatusCode::Ok;
    }
    if (terminal()) {
        return core::StatusCode::InvalidArgument;
    }
    bool allowed = false;
    if (next == PipelineState::Cancelled) {
        allowed = true;
    } else if (next == PipelineState::Failed) {
        allowed = true;
    } else {
        switch (state_) {
        case PipelineState::Created:
            allowed = next == PipelineState::Initializing;
            break;
        case PipelineState::Initializing:
            allowed = next == PipelineState::Discovering || next == PipelineState::PortScanning ||
                      next == PipelineState::DetectingServices || next == PipelineState::DetectingOS ||
                      next == PipelineState::Serializing || next == PipelineState::Completed;
            break;
        case PipelineState::Discovering:
            allowed = next == PipelineState::PortScanning || next == PipelineState::DetectingServices ||
                      next == PipelineState::DetectingOS || next == PipelineState::Serializing ||
                      next == PipelineState::Completed;
            break;
        case PipelineState::PortScanning:
            allowed = next == PipelineState::DetectingServices || next == PipelineState::DetectingOS ||
                      next == PipelineState::Serializing || next == PipelineState::Completed;
            break;
        case PipelineState::DetectingServices:
            allowed = next == PipelineState::DetectingOS || next == PipelineState::Serializing ||
                      next == PipelineState::Completed;
            break;
        case PipelineState::DetectingOS:
            allowed = next == PipelineState::Serializing || next == PipelineState::Completed;
            break;
        case PipelineState::Serializing:
            allowed = next == PipelineState::Completed;
            break;
        case PipelineState::Completed:
        case PipelineState::Cancelled:
        case PipelineState::Failed:
            allowed = false;
            break;
        }
    }
    if (!allowed) {
        return core::StatusCode::InvalidArgument;
    }
    state_ = next;
    return core::StatusCode::Ok;
}

void ScanSession::cancel() noexcept
{
    if (cancel_requested_ || terminal()) {
        return;
    }
    cancel_requested_ = true;
    if (cancel_callback_) {
        try {
            cancel_callback_();
        } catch (...) {
            // Cancellation is best effort and must remain idempotent/noexcept.
        }
    }
    if (!terminal()) {
        (void)transition(PipelineState::Cancelled);
    }
    finish_clock();
    emit(ScanEvent{ScanEventType::ScanCancelled, id_, std::nullopt, std::nullopt, std::nullopt,
                   "scan cancelled", finished_at_});
}

void ScanSession::set_cancel_callback(std::function<void()> callback)
{
    cancel_callback_ = std::move(callback);
}

void ScanSession::emit(ScanEvent event) noexcept
{
    if (!sink_) {
        return;
    }
    if ((terminal() && event.type != ScanEventType::ScanCompleted &&
         event.type != ScanEventType::ScanCancelled && event.type != ScanEventType::ScanFailed) ||
        (cancelled() && event.type != ScanEventType::ScanCancelled && event.type != ScanEventType::ScanFailed)) {
        return;
    }
    event.session_id = id_;
    if (event.timestamp == std::chrono::steady_clock::time_point{}) {
        event.timestamp = std::chrono::steady_clock::now();
    }
    try {
        sink_(event);
    } catch (...) {
        // An observer cannot invalidate orchestration state.
    }
}

const ScanCounters &ScanSession::counters() const noexcept { return counters_; }
ScanCounters &ScanSession::counters() noexcept { return counters_; }
const std::optional<output::ScanReport> &ScanSession::report() const noexcept { return report_; }
void ScanSession::set_report(output::ScanReport report) { report_ = std::move(report); }
const std::string &ScanSession::error_message() const noexcept { return error_message_; }
void ScanSession::set_error(std::string message) { error_message_ = std::move(message); }
std::chrono::steady_clock::time_point ScanSession::started_at() const noexcept { return started_at_; }
std::chrono::steady_clock::time_point ScanSession::finished_at() const noexcept { return finished_at_; }
void ScanSession::finish_clock() noexcept { finished_at_ = std::chrono::steady_clock::now(); }

} // namespace skan::orchestrator
