#ifndef SKAN_SCANENGINE_TIMING_PROFILE_HPP
#define SKAN_SCANENGINE_TIMING_PROFILE_HPP

#include <chrono>
#include <cstddef>
#include <string_view>

#include "core/status.hpp"

namespace skan::scanengine {

enum class TimingProfileId : unsigned char {
    T0 = 0,
    T1,
    T2,
    T3,
    T4,
    T5
};

struct TimingProfile final {
    TimingProfileId id{TimingProfileId::T3};
    std::size_t min_parallelism{1U};
    std::size_t max_parallelism{64U};
    std::size_t initial_parallelism{8U};
    std::chrono::milliseconds minimum_timeout{50};
    std::chrono::milliseconds maximum_timeout{30000};
    double rtt_multiplier{4.0};
    double backoff_factor{0.5};
    std::size_t timeout_threshold{2U};
    std::size_t recovery_threshold{4U};
    double drop_rate_alpha{0.125};
    std::size_t max_retries{0U};

    core::StatusCode validate() const noexcept;
    static TimingProfile for_id(TimingProfileId id) noexcept;
    static core::StatusCode parse(std::string_view text, TimingProfile &profile) noexcept;
};

const char *timing_profile_name(TimingProfileId id) noexcept;

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_TIMING_PROFILE_HPP
