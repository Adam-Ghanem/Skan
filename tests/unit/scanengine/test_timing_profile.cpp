#include <cassert>
#include <chrono>

#include "scanengine/timing_profile.hpp"

int main()
{
    using namespace skan::scanengine;
    for (unsigned int index = 0U; index <= 5U; ++index) {
        const auto id = static_cast<TimingProfileId>(index);
        const TimingProfile profile = TimingProfile::for_id(id);
        assert(profile.validate() == skan::core::StatusCode::Ok);
        assert(timing_profile_name(id)[0] == 'T');
        assert(static_cast<unsigned int>(timing_profile_name(id)[1] - '0') == index);
    }

    TimingProfile parsed;
    assert(TimingProfile::parse("T3", parsed) == skan::core::StatusCode::Ok);
    assert(parsed.id == TimingProfileId::T3);
    assert(TimingProfile::parse("T6", parsed) == skan::core::StatusCode::InvalidArgument);
    assert(TimingProfile::parse("T", parsed) == skan::core::StatusCode::InvalidArgument);

    TimingProfile invalid = parsed;
    invalid.min_parallelism = 0U;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid = parsed;
    invalid.maximum_timeout = std::chrono::milliseconds{1};
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    invalid = parsed;
    invalid.backoff_factor = 1.0;
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    return 0;
}
