#include "scanengine/congestion.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace skan::scanengine {

CongestionController::CongestionController(CongestionConfig config) : config_(config)
{
    state_.min_parallelism = config_.min_parallelism;
    state_.max_parallelism = config_.max_parallelism;
    state_.current_parallelism = config_.initial_parallelism;
    clamp_parallelism();
}

bool CongestionController::valid() const noexcept
{
    return config_.min_parallelism > 0U && config_.max_parallelism >= config_.min_parallelism &&
           config_.initial_parallelism >= config_.min_parallelism &&
           config_.initial_parallelism <= config_.max_parallelism && config_.timeout_threshold > 0U &&
           config_.recovery_threshold > 0U && config_.backoff_factor > 0.0 && config_.backoff_factor < 1.0 &&
           std::isfinite(config_.backoff_factor) && config_.drop_rate_alpha > 0.0 &&
           config_.drop_rate_alpha <= 1.0 && std::isfinite(config_.drop_rate_alpha);
}

void CongestionController::clamp_parallelism() noexcept
{
    state_.current_parallelism = std::clamp(
        state_.current_parallelism,
        config_.min_parallelism,
        config_.max_parallelism);
}

void CongestionController::on_response() noexcept
{
    ++state_.responses;
    state_.consecutive_timeouts = 0U;
    if (state_.consecutive_successes < std::numeric_limits<std::size_t>::max()) {
        ++state_.consecutive_successes;
    }
    state_.drop_rate = (1.0 - config_.drop_rate_alpha) * state_.drop_rate;
    if (state_.consecutive_successes >= config_.recovery_threshold) {
        if (state_.current_parallelism < state_.max_parallelism) {
            ++state_.current_parallelism;
        }
        state_.consecutive_successes = 0U;
    }
    clamp_parallelism();
}

void CongestionController::on_timeout() noexcept
{
    ++state_.timeouts;
    state_.consecutive_successes = 0U;
    if (state_.consecutive_timeouts < std::numeric_limits<std::size_t>::max()) {
        ++state_.consecutive_timeouts;
    }
    state_.drop_rate = config_.drop_rate_alpha + (1.0 - config_.drop_rate_alpha) * state_.drop_rate;
    if (state_.consecutive_timeouts >= config_.timeout_threshold) {
        const double scaled = static_cast<double>(state_.current_parallelism) * config_.backoff_factor;
        const double maximum = static_cast<double>(std::numeric_limits<std::size_t>::max());
        const std::size_t next = scaled < 1.0
                                     ? 1U
                                     : scaled >= maximum ? std::numeric_limits<std::size_t>::max()
                                                        : static_cast<std::size_t>(scaled);
        state_.current_parallelism = std::max(config_.min_parallelism, next);
        ++state_.backoff_count;
        state_.consecutive_timeouts = 0U;
    }
    clamp_parallelism();
}

const CongestionState &CongestionController::state() const noexcept
{
    return state_;
}

const CongestionConfig &CongestionController::config() const noexcept
{
    return config_;
}

} // namespace skan::scanengine
