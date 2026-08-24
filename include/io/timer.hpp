#ifndef SKAN_IO_TIMER_HPP
#define SKAN_IO_TIMER_HPP

#include <chrono>
#include <cstdint>
#include <functional>

namespace skan::io {

using TimerId = std::uint64_t;
using TimerCallback = std::function<void()>;
using TimerClock = std::chrono::steady_clock;
using TimerDuration = TimerClock::duration;

/** A timer specification based on the monotonic steady clock. */
struct Timer final {
    TimerId id{0U};
    TimerClock::time_point deadline{};
    TimerCallback callback{};
    bool cancelled{false};
};

} // namespace skan::io

#endif // SKAN_IO_TIMER_HPP
