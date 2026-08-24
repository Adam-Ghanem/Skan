#include <cassert>

#include "scanengine/congestion.hpp"

int main()
{
    using namespace skan::scanengine;
    CongestionConfig config;
    config.min_parallelism = 2U;
    config.max_parallelism = 16U;
    config.initial_parallelism = 8U;
    config.timeout_threshold = 2U;
    config.recovery_threshold = 3U;
    config.backoff_factor = 0.5;
    config.drop_rate_alpha = 0.25;
    CongestionController controller(config);
    assert(controller.valid());
    assert(controller.state().current_parallelism == 8U);

    controller.on_timeout();
    assert(controller.state().current_parallelism == 8U);
    assert(controller.state().timeouts == 1U);
    assert(controller.state().drop_rate > 0.24 && controller.state().drop_rate < 0.26);
    controller.on_timeout();
    assert(controller.state().current_parallelism == 4U);
    assert(controller.state().backoff_count == 1U);
    assert(controller.state().consecutive_timeouts == 0U);

    controller.on_response();
    controller.on_response();
    assert(controller.state().current_parallelism == 4U);
    controller.on_response();
    assert(controller.state().current_parallelism == 5U);
    assert(controller.state().consecutive_successes == 0U);

    for (unsigned int count = 0U; count < 20U; ++count) {
        controller.on_timeout();
    }
    assert(controller.state().current_parallelism >= config.min_parallelism);
    assert(controller.state().current_parallelism <= config.max_parallelism);
    assert(controller.state().drop_rate <= 1.0);

    CongestionConfig invalid = config;
    invalid.initial_parallelism = 1U;
    CongestionController invalid_controller(invalid);
    assert(!invalid_controller.valid());
    return 0;
}
