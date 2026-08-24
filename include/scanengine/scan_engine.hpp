#ifndef SKAN_SCANENGINE_SCAN_ENGINE_HPP
#define SKAN_SCANENGINE_SCAN_ENGINE_HPP

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "scanengine/adaptive_scheduler.hpp"

#include "scanengine/scan_metrics.hpp"

namespace skan::scanengine {

class TimingController final {
public:
    explicit TimingController(TimingProfile profile = TimingProfile::for_id(TimingProfileId::T3));

    core::StatusCode validate() const noexcept;
    std::size_t parallelism_limit(std::size_t configured_limit) const noexcept;
    std::chrono::milliseconds timeout() const noexcept;
    bool should_retry(std::size_t retry_count) const noexcept;
    void on_submitted(std::size_t outstanding) noexcept;
    void on_response(std::chrono::milliseconds rtt) noexcept;
    void on_timeout() noexcept;
    const TimingProfile &profile() const noexcept;
    const RttEstimator &rtt() const noexcept;
    const CongestionController &congestion() const noexcept;
    const ScanMetrics &metrics() const noexcept;
    ScanMetrics &metrics() noexcept;

private:
    TimingProfile profile_;
    RttEstimator rtt_;
    CongestionController congestion_;
    ScanMetrics metrics_;
};

class ScanEngine final {
public:
    explicit ScanEngine(TimingProfile profile = TimingProfile::for_id(TimingProfileId::T3));

    core::StatusCode validate() const noexcept;
    std::unique_ptr<ScanGroup> create_group(std::string name) const;
    TimingController create_timing_controller() const;
    const TimingProfile &profile() const noexcept;

private:
    TimingProfile profile_;
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_SCAN_ENGINE_HPP
