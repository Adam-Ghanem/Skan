#include <cassert>
#include <chrono>
#include <limits>

#include "scanengine/rtt_estimator.hpp"

int main()
{
    using namespace skan::scanengine;
    RttEstimatorConfig config;
    config.minimum_timeout = std::chrono::milliseconds{50};
    config.maximum_timeout = std::chrono::milliseconds{1000};
    config.alpha = 0.125;
    config.beta = 0.25;
    config.multiplier = 4.0;
    RttEstimator estimator(config);

    assert(estimator.sample_count() == 0U);
    assert(estimator.timeout() == std::chrono::milliseconds{50});
    assert(!estimator.observe(std::chrono::milliseconds{100}, RttSampleValidity::Timeout));
    assert(estimator.sample_count() == 0U);
    assert(estimator.observe(std::chrono::milliseconds{100}, RttSampleValidity::ValidResponse));
    assert(estimator.sample_count() == 1U);
    assert(estimator.srtt().value() == std::chrono::milliseconds{100});
    assert(estimator.rttvar().value() == std::chrono::milliseconds{50});
    assert(estimator.timeout() == std::chrono::milliseconds{300});

    assert(estimator.observe(std::chrono::milliseconds{200}, RttSampleValidity::ValidResponse));
    assert(estimator.sample_count() == 2U);
    assert(estimator.srtt().value() == std::chrono::milliseconds{112});
    assert(estimator.rttvar().value() == std::chrono::milliseconds{62});
    assert(estimator.timeout() == std::chrono::milliseconds{362});
    assert(!estimator.observe(std::chrono::milliseconds{1}, RttSampleValidity::Duplicate));
    assert(!estimator.observe(std::chrono::milliseconds{1}, RttSampleValidity::LateResponse));
    assert(!estimator.observe(std::chrono::milliseconds{1}, RttSampleValidity::MalformedResponse));
    assert(estimator.sample_count() == 2U);

    assert(estimator.observe(std::chrono::milliseconds{5000}, RttSampleValidity::ValidResponse));
    assert(estimator.timeout() == config.maximum_timeout);
    assert(estimator.observe(std::chrono::milliseconds{std::numeric_limits<long long>::max()},
                             RttSampleValidity::ValidResponse));
    assert(estimator.timeout() == config.maximum_timeout);
    assert(estimator.average_sample_ms() > 0.0);
    return 0;
}
