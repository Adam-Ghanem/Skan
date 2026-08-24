#ifndef SKAN_SCANENGINE_CONGESTION_HPP
#define SKAN_SCANENGINE_CONGESTION_HPP

#include <cstddef>

namespace skan::scanengine {

struct CongestionConfig final {
    std::size_t min_parallelism{1U};
    std::size_t max_parallelism{64U};
    std::size_t initial_parallelism{8U};
    std::size_t timeout_threshold{2U};
    std::size_t recovery_threshold{4U};
    double backoff_factor{0.5};
    double drop_rate_alpha{0.125};
};

struct CongestionState final {
    std::size_t min_parallelism{1U};
    std::size_t max_parallelism{1U};
    std::size_t current_parallelism{1U};
    double drop_rate{0.0};
    std::size_t responses{0U};
    std::size_t timeouts{0U};
    std::size_t consecutive_timeouts{0U};
    std::size_t consecutive_successes{0U};
    std::size_t backoff_count{0U};
};

class CongestionController final {
public:
    explicit CongestionController(CongestionConfig config = {});

    bool valid() const noexcept;
    void on_response() noexcept;
    void on_timeout() noexcept;
    const CongestionState &state() const noexcept;
    const CongestionConfig &config() const noexcept;

private:
    void clamp_parallelism() noexcept;

    CongestionConfig config_;
    CongestionState state_;
};

} // namespace skan::scanengine

#endif // SKAN_SCANENGINE_CONGESTION_HPP
