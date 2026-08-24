#include "scanengine/scan_engine.hpp"

#include <algorithm>
#include <utility>

namespace skan::scanengine {

TimingController::TimingController(TimingProfile profile)
    : profile_(profile),
      rtt_(RttEstimatorConfig{profile.minimum_timeout, profile.maximum_timeout, 0.125, 0.25, profile.rtt_multiplier}),
      congestion_(CongestionConfig{profile.min_parallelism,
                                   profile.max_parallelism,
                                   profile.initial_parallelism,
                                   profile.timeout_threshold,
                                   profile.recovery_threshold,
                                   profile.backoff_factor,
                                   profile.drop_rate_alpha})
{
}

core::StatusCode TimingController::validate() const noexcept
{
    return profile_.validate() == core::StatusCode::Ok && congestion_.valid()
               ? core::StatusCode::Ok
               : core::StatusCode::InvalidArgument;
}

std::size_t TimingController::parallelism_limit(std::size_t configured_limit) const noexcept
{
    return configured_limit == 0U ? congestion_.state().current_parallelism
                                  : std::min(configured_limit, congestion_.state().current_parallelism);
}

std::chrono::milliseconds TimingController::timeout() const noexcept
{
    return rtt_.timeout();
}

bool TimingController::should_retry(std::size_t retry_count) const noexcept
{
    return retry_count < profile_.max_retries;
}

void TimingController::on_submitted(std::size_t outstanding) noexcept
{
    ++metrics_.total_submitted;
    metrics_.set_parallelism(outstanding, outstanding);
}

void TimingController::on_response(std::chrono::milliseconds rtt) noexcept
{
    ++metrics_.completed;
    (void)rtt_.observe(rtt, RttSampleValidity::ValidResponse);
    congestion_.on_response();
    metrics_.record_rtt(rtt);
    metrics_.estimated_drop_rate = congestion_.state().drop_rate;
    metrics_.current_parallelism = congestion_.state().current_parallelism;
}

void TimingController::on_timeout() noexcept
{
    congestion_.on_timeout();
    ++metrics_.timed_out;
    ++metrics_.timeout_count;
    metrics_.estimated_drop_rate = congestion_.state().drop_rate;
    metrics_.current_parallelism = congestion_.state().current_parallelism;
}

const TimingProfile &TimingController::profile() const noexcept { return profile_; }
const RttEstimator &TimingController::rtt() const noexcept { return rtt_; }
const CongestionController &TimingController::congestion() const noexcept { return congestion_; }
const ScanMetrics &TimingController::metrics() const noexcept { return metrics_; }
ScanMetrics &TimingController::metrics() noexcept { return metrics_; }

ScanEngine::ScanEngine(TimingProfile profile) : profile_(profile)
{
}

core::StatusCode ScanEngine::validate() const noexcept
{
    return profile_.validate();
}

TimingController ScanEngine::create_timing_controller() const
{
    return TimingController{profile_};
}

std::unique_ptr<ScanGroup> ScanEngine::create_group(std::string name) const
{
    if (validate() != core::StatusCode::Ok) {
        return nullptr;
    }
    return std::make_unique<ScanGroup>(std::move(name), profile_);
}

const TimingProfile &ScanEngine::profile() const noexcept
{
    return profile_;
}

} // namespace skan::scanengine
