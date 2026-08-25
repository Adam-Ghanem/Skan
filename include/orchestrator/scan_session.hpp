#ifndef SKAN_ORCHESTRATOR_SCAN_SESSION_HPP
#define SKAN_ORCHESTRATOR_SCAN_SESSION_HPP

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "core/status.hpp"
#include "io/io_engine.hpp"
#include "orchestrator/scan_events.hpp"
#include "output/result_model.hpp"

namespace skan::orchestrator {

enum class PipelineState {
    Created = 0,
    Initializing,
    Discovering,
    PortScanning,
    DetectingServices,
    DetectingOS,
    Serializing,
    Completed,
    Cancelled,
    Failed
};

const char *pipeline_state_name(PipelineState state) noexcept;

struct ScanCounters final {
    std::size_t hosts_total{0U};
    std::size_t hosts_up{0U};
    std::size_t hosts_down{0U};
    std::size_t hosts_unknown{0U};
    std::size_t ports_scanned{0U};
    std::size_t ports_open{0U};
    std::size_t ports_closed{0U};
    std::size_t ports_filtered{0U};
    std::size_t services_detected{0U};
    std::size_t os_matches{0U};
    std::size_t probes_sent{0U};
    std::size_t probes_completed{0U};
    std::size_t probes_timed_out{0U};
    std::size_t peak_pending{0U};
};

class ScanSession final {
public:
    explicit ScanSession(std::string session_id, ScanEventSink sink = {});
    ~ScanSession();

    ScanSession(const ScanSession &) = delete;
    ScanSession &operator=(const ScanSession &) = delete;

    const std::string &id() const noexcept;
    io::IOEngine &io_engine() noexcept;
    const io::IOEngine &io_engine() const noexcept;

    PipelineState state() const noexcept;
    core::StatusCode transition(PipelineState next) noexcept;
    bool cancelled() const noexcept;
    bool terminal() const noexcept;
    void cancel() noexcept;
    void set_cancel_callback(std::function<void()> callback);

    void emit(ScanEvent event) noexcept;
    const ScanCounters &counters() const noexcept;
    ScanCounters &counters() noexcept;

    const std::optional<output::ScanReport> &report() const noexcept;
    void set_report(output::ScanReport report);
    const std::string &error_message() const noexcept;
    void set_error(std::string message);

    std::chrono::steady_clock::time_point started_at() const noexcept;
    std::chrono::steady_clock::time_point finished_at() const noexcept;
    void finish_clock() noexcept;

private:
    std::string id_;
    std::unique_ptr<io::IOEngine> io_engine_;
    ScanEventSink sink_;
    std::function<void()> cancel_callback_;
    PipelineState state_{PipelineState::Created};
    bool cancel_requested_{false};
    ScanCounters counters_;
    std::optional<output::ScanReport> report_;
    std::string error_message_;
    std::chrono::steady_clock::time_point started_at_;
    std::chrono::steady_clock::time_point finished_at_;
};

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_SESSION_HPP
