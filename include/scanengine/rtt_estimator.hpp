#ifndef SKAN_SCANENGINE_RTT_ESTIMATOR_HPP
#define SKAN_SCANENGINE_RTT_ESTIMATOR_HPP

#include <chrono>
#include <cstddef>
#include <optional>

namespace skan::scanengine {

enum class RttSampleValidity : unsigned char {
    ValidResponse = 0,
    Timeout,
    Duplicate,
    LateResponse,
    MalformedResponse
};

struct RttEstimatorConfig final {
    std::chrono::milliseconds minimum_timeout{50};
    std::chrono::milliseconds maximum_timeout{30000};
    double alpha{0.125};
    double beta{0.25};
    double multiplier{4.0};
};

class RttEstimator final {
public:
    explicit RttEstimator(RttEstimatorConfig config = {});

    bool observe(std::chrono::milliseconds sample, RttSampleValidity validity) noexcept;
    std::chrono::milliseconds timeout() const noexcept;
    std::optional<std::chrono::milliseconds> srtt() const noexcept;
    std::optional<std::chrono::milliseconds> rttvar() const noexcept;
    std::optional<std::chrono::milliseconds> last_sample() const noexcept;
    std::optional<std::chrono::milliseconds> minimum_sample() const noexcept;
    std::optional<std::chrono::milliseconds> maximum_sample() const noexcept;
    double average_sample_ms() const noexcept;
    std::size_t sample_count() const noexcept;
    const RttEstimatorConfig &config() const noexcept;

private:
    std::chrono::milliseconds clamp_timeout(long double value) const noexcept;

    RttEstimatorConfig config_;
    std::optional<long double> srtt_ms_;
    std::optional<long double> rttvar_ms_;
    std::optional<std::chrono::milliseconds> last_sample_;
    std::optional<std::chrono::milliseconds> minimum_sample_;
    std::optional<std::chrono::milliseconds> maximum_sample_;
    long double sample_sum_ms_{0.0L};
    std::size_t sample_count_{0U};
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_RTT_ESTIMATOR_HPP
