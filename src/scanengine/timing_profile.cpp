#include "scanengine/timing_profile.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <limits>

namespace skan::scanengine {
namespace {

constexpr std::array<TimingProfile, 6U> kProfiles{
    TimingProfile{TimingProfileId::T0, 1U, 4U, 1U, std::chrono::milliseconds{500}, std::chrono::milliseconds{30000}, 5.0, 0.5, 1U, 8U, 0.125, 0U},
    TimingProfile{TimingProfileId::T1, 1U, 8U, 2U, std::chrono::milliseconds{250}, std::chrono::milliseconds{30000}, 5.0, 0.5, 2U, 6U, 0.125, 0U},
    TimingProfile{TimingProfileId::T2, 1U, 32U, 4U, std::chrono::milliseconds{100}, std::chrono::milliseconds{30000}, 4.5, 0.5, 2U, 5U, 0.125, 0U},
    TimingProfile{TimingProfileId::T3, 1U, 64U, 8U, std::chrono::milliseconds{50}, std::chrono::milliseconds{30000}, 4.0, 0.5, 2U, 4U, 0.125, 0U},
    TimingProfile{TimingProfileId::T4, 2U, 128U, 16U, std::chrono::milliseconds{50}, std::chrono::milliseconds{10000}, 3.0, 0.5, 2U, 3U, 0.125, 0U},
    TimingProfile{TimingProfileId::T5, 4U, 256U, 32U, std::chrono::milliseconds{25}, std::chrono::milliseconds{5000}, 2.5, 0.5, 1U, 2U, 0.125, 0U}};

} // namespace

core::StatusCode TimingProfile::validate() const noexcept
{
    if (min_parallelism == 0U || max_parallelism < min_parallelism || initial_parallelism < min_parallelism ||
        initial_parallelism > max_parallelism) {
        return core::StatusCode::InvalidArgument;
    }
    if (minimum_timeout.count() <= 0 || maximum_timeout < minimum_timeout ||
        rtt_multiplier <= 0.0 || !std::isfinite(rtt_multiplier) || backoff_factor <= 0.0 || backoff_factor >= 1.0 ||
        !std::isfinite(backoff_factor) || timeout_threshold == 0U || recovery_threshold == 0U ||
        drop_rate_alpha <= 0.0 || drop_rate_alpha > 1.0 || !std::isfinite(drop_rate_alpha)) {
        return core::StatusCode::InvalidArgument;
    }
    return core::StatusCode::Ok;
}

TimingProfile TimingProfile::for_id(TimingProfileId id) noexcept
{
    const auto index = static_cast<std::size_t>(id);
    return index < kProfiles.size() ? kProfiles[index] : kProfiles[3U];
}

core::StatusCode TimingProfile::parse(std::string_view text, TimingProfile &profile) noexcept
{
    if (text.size() != 2U || text.front() != 'T' || text[1] < '0' || text[1] > '5') {
        return core::StatusCode::InvalidArgument;
    }
    profile = for_id(static_cast<TimingProfileId>(static_cast<unsigned int>(text[1] - '0')));
    return core::StatusCode::Ok;
}

const char *timing_profile_name(TimingProfileId id) noexcept
{
    switch (id) {
    case TimingProfileId::T0:
        return "T0";
    case TimingProfileId::T1:
        return "T1";
    case TimingProfileId::T2:
        return "T2";
    case TimingProfileId::T3:
        return "T3";
    case TimingProfileId::T4:
        return "T4";
    case TimingProfileId::T5:
        return "T5";
    }
    return "T3";
}

} // namespace skan::scanengine
