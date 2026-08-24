#ifndef SKAN_SCANENGINE_SCAN_GROUP_HPP
#define SKAN_SCANENGINE_SCAN_GROUP_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>

#include "scanengine/congestion.hpp"
#include "scanengine/rtt_estimator.hpp"
#include "scanengine/scan_metrics.hpp"
#include "scanengine/timing_profile.hpp"

namespace skan::scanengine {

using ScanWorkId = std::uint64_t;

enum class ScanWorkState : unsigned char {
    Queued = 0,
    Submitted,
    Completed,
    TimedOut,
    Cancelled,
    Failed
};

struct ScanWorkItem final {
    ScanWorkId id{0U};
    std::string target;
    std::string protocol_metadata;
    ScanTimePoint created_at{};
    ScanTimePoint submitted_at{};
    ScanTimePoint deadline{};
    std::size_t retry_count{0U};
    ScanWorkState state{ScanWorkState::Queued};
};

class ScanGroup final {
public:
    explicit ScanGroup(
        std::string name,
        TimingProfile profile = TimingProfile::for_id(TimingProfileId::T3));

    core::StatusCode validate() const noexcept;
    core::StatusCode enqueue(std::string target, std::string protocol_metadata, ScanWorkId &id);
    core::StatusCode enqueue(ScanWorkItem item);
    std::optional<ScanWorkItem> next_queued();
    bool requeue_for_retry(ScanWorkItem item) noexcept;
    bool cancel(ScanWorkId id) noexcept;
    void cancel_all() noexcept;

    bool mark_submitted(ScanWorkId id, ScanTimePoint submitted_at, ScanTimePoint deadline) noexcept;
    bool mark_completed(ScanWorkId id) noexcept;
    bool mark_timed_out(ScanWorkId id) noexcept;
    bool mark_failed(ScanWorkId id) noexcept;

    const std::string &name() const noexcept;
    const TimingProfile &profile() const noexcept;
    TimingProfile &profile() noexcept;
    const ScanMetrics &metrics() const noexcept;
    ScanMetrics &metrics() noexcept;
    const RttEstimator &rtt() const noexcept;
    RttEstimator &rtt() noexcept;
    const CongestionController &congestion() const noexcept;
    CongestionController &congestion() noexcept;
    std::size_t queued_count() const noexcept;
    std::size_t outstanding_count() const noexcept;
    std::size_t total_count() const noexcept;
    std::optional<ScanWorkState> state(ScanWorkId id) const noexcept;

private:
    void update_parallelism() noexcept;

    std::string name_;
    TimingProfile profile_;
    RttEstimator rtt_;
    CongestionController congestion_;
    ScanMetrics metrics_;
    std::deque<ScanWorkId> queue_;
    std::unordered_map<ScanWorkId, ScanWorkItem> items_;
    ScanWorkId next_id_{1U};
};

const char *scan_work_state_name(ScanWorkState state) noexcept;

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_SCAN_GROUP_HPP
