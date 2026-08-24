#ifndef SKAN_SCANENGINE_ADAPTIVE_SCHEDULER_HPP
#define SKAN_SCANENGINE_ADAPTIVE_SCHEDULER_HPP

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "io/io_engine.hpp"
#include "scanengine/scan_group.hpp"

namespace skan::scanengine {

enum class ScanCompletionState : unsigned char {
    ValidResponse = 0,
    Timeout,
    Duplicate,
    LateResponse,
    MalformedResponse,
    Failed
};

struct ScanCompletion final {
    ScanWorkId id{0U};
    ScanCompletionState state{ScanCompletionState::ValidResponse};
    std::optional<std::chrono::milliseconds> rtt;
};

using ScanCompletionCallback = std::function<void(const ScanCompletion &)>;

class ScanTransport {
public:
    virtual ~ScanTransport() = default;
    virtual core::StatusCode submit(const ScanWorkItem &work, ScanCompletionCallback callback) = 0;
    virtual core::StatusCode cancel(ScanWorkId id) noexcept = 0;
};

class RecordingScanTransport final : public ScanTransport {
public:
    core::StatusCode submit(const ScanWorkItem &work, ScanCompletionCallback callback) override;
    core::StatusCode cancel(ScanWorkId id) noexcept override;

    void deliver(const ScanCompletion &completion);
    const std::vector<ScanWorkItem> &submissions() const noexcept;
    std::size_t active_callback_count() const noexcept;

private:
    std::vector<ScanWorkItem> submissions_;
    std::unordered_map<ScanWorkId, ScanCompletionCallback> callbacks_;
};

class AdaptiveScheduler final {
public:
    AdaptiveScheduler(io::IOEngine &engine, ScanTransport &transport, ScanGroup &group);
    ~AdaptiveScheduler();

    AdaptiveScheduler(const AdaptiveScheduler &) = delete;
    AdaptiveScheduler &operator=(const AdaptiveScheduler &) = delete;

    core::StatusCode start() noexcept;
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;
    void receive(const ScanCompletion &completion) noexcept;
    core::StatusCode cancel(ScanWorkId id) noexcept;
    void shutdown() noexcept;

    bool complete() const noexcept;
    std::size_t pending_count() const noexcept;
    core::StatusCode status() const noexcept;

private:
    struct Pending final {
        ScanWorkItem work;
        ScanTimePoint sent_at{};
        io::TimerId timer_id{0U};
    };

    void pump() noexcept;
    void on_timeout(ScanWorkId id) noexcept;
    void complete_pending(const ScanCompletion &completion) noexcept;
    void fail_pending(ScanWorkId id, bool malformed) noexcept;
    void finish_if_idle() noexcept;
    void update_adaptive_state() noexcept;

    io::IOEngine &engine_;
    ScanTransport &transport_;
    ScanGroup &group_;
    std::unordered_map<ScanWorkId, Pending> pending_;
    std::unordered_set<ScanWorkId> completed_ids_;
    std::unordered_set<ScanWorkId> expired_ids_;
    core::StatusCode status_{core::StatusCode::Ok};
    bool started_{false};
    bool stopped_{false};
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_ADAPTIVE_SCHEDULER_HPP
