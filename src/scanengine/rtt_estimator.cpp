#include "scanengine/rtt_estimator.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace skan::scanengine {

RttEstimator::RttEstimator(RttEstimatorConfig config) : config_(config)
{
}

bool RttEstimator::observe(std::chrono::milliseconds sample, RttSampleValidity validity) noexcept
{
    if (validity != RttSampleValidity::ValidResponse || sample.count() < 0 ||
        !std::isfinite(static_cast<double>(sample.count()))) {
        return false;
    }
    const long double value = static_cast<long double>(sample.count());
    if (!srtt_ms_.has_value()) {
        srtt_ms_ = value;
        rttvar_ms_ = value / 2.0L;
    } else {
        const long double difference = std::fabs(*srtt_ms_ - value);
        rttvar_ms_ = (1.0L - static_cast<long double>(config_.beta)) * *rttvar_ms_ +
                     static_cast<long double>(config_.beta) * difference;
        srtt_ms_ = (1.0L - static_cast<long double>(config_.alpha)) * *srtt_ms_ +
                   static_cast<long double>(config_.alpha) * value;
    }
    last_sample_ = sample;
    minimum_sample_ = minimum_sample_.has_value() ? std::min(*minimum_sample_, sample) : sample;
    maximum_sample_ = maximum_sample_.has_value() ? std::max(*maximum_sample_, sample) : sample;
    sample_sum_ms_ += value;
    ++sample_count_;
    return true;
}

std::chrono::milliseconds RttEstimator::clamp_timeout(long double value) const noexcept
{
    const long double minimum = static_cast<long double>(config_.minimum_timeout.count());
    const long double maximum = static_cast<long double>(config_.maximum_timeout.count());
    if (!std::isfinite(static_cast<double>(value))) {
        return config_.maximum_timeout;
    }
    const long double bounded = std::clamp(value, minimum, maximum);
    if (bounded >= static_cast<long double>(std::numeric_limits<long long>::max())) {
        return config_.maximum_timeout;
    }
    return std::chrono::milliseconds{static_cast<long long>(bounded)};
}

std::chrono::milliseconds RttEstimator::timeout() const noexcept
{
    if (!srtt_ms_.has_value() || !rttvar_ms_.has_value()) {
        return config_.minimum_timeout;
    }
    return clamp_timeout(*srtt_ms_ + static_cast<long double>(config_.multiplier) * *rttvar_ms_);
}

std::optional<std::chrono::milliseconds> RttEstimator::srtt() const noexcept
{
    if (!srtt_ms_.has_value()) {
        return std::nullopt;
    }
    return clamp_timeout(*srtt_ms_);
}

std::optional<std::chrono::milliseconds> RttEstimator::rttvar() const noexcept
{
    if (!rttvar_ms_.has_value()) {
        return std::nullopt;
    }
    return clamp_timeout(*rttvar_ms_);
}

std::optional<std::chrono::milliseconds> RttEstimator::last_sample() const noexcept
{
    return last_sample_;
}

std::optional<std::chrono::milliseconds> RttEstimator::minimum_sample() const noexcept
{
    return minimum_sample_;
}

std::optional<std::chrono::milliseconds> RttEstimator::maximum_sample() const noexcept
{
    return maximum_sample_;
}

double RttEstimator::average_sample_ms() const noexcept
{
    if (sample_count_ == 0U) {
        return 0.0;
    }
    return static_cast<double>(sample_sum_ms_ / static_cast<long double>(sample_count_));
}

std::size_t RttEstimator::sample_count() const noexcept
{
    return sample_count_;
}

const RttEstimatorConfig &RttEstimator::config() const noexcept
{
    return config_;
}

} // namespace skan::scanengine
