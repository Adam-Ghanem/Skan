#ifndef SKAN_IO_IO_ENGINE_HPP
#define SKAN_IO_IO_ENGINE_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core/status.hpp"
#include "io/event.hpp"
#include "io/timer.hpp"

namespace skan::io {

/**
 * Single-thread-affine Linux event reactor backed by epoll.
 * Events are borrowed: callers own Event objects and keep them alive while registered.
 */
class IOEngine final {
public:
    IOEngine() noexcept;
    ~IOEngine() noexcept;

    IOEngine(const IOEngine &) = delete;
    IOEngine &operator=(const IOEngine &) = delete;
    IOEngine(IOEngine &&) = delete;
    IOEngine &operator=(IOEngine &&) = delete;

    /** Return the constructor status, including failure to create the epoll instance. */
    core::StatusCode initialization_status() const noexcept;

    /** Register an event owned by the caller. */
    core::StatusCode add(Event &event) noexcept;

    /** Change the mask of an already registered event. */
    core::StatusCode modify(Event &event) noexcept;

    /** Unregister an event without destroying it. */
    core::StatusCode remove(Event &event) noexcept;

    /** Run until stop() is called or an unrecoverable wait error occurs. */
    core::StatusCode run() noexcept;

    /** Dispatch one bounded reactor iteration; a negative timeout means no user bound. */
    core::StatusCode run_once(int timeout_ms) noexcept;

    /** Request that the current or next run loop exit cleanly. */
    void stop() noexcept;

    /** Close the reactor and detach all borrowed events. Safe to call more than once. */
    core::StatusCode shutdown() noexcept;

    bool running() const noexcept;

    /** Schedule a one-shot callback against the monotonic steady clock. */
    TimerId schedule(TimerDuration delay, TimerCallback callback);

    /** Cancel a pending timer. Cancelling an unknown timer is a no-op success. */
    core::StatusCode cancel(TimerId timer_id) noexcept;

    /** Set O_NONBLOCK on a descriptor without changing process-wide state. */
    static core::StatusCode set_nonblocking(int file_descriptor) noexcept;

private:
    struct TimerQueueEntry final {
        TimerClock::time_point deadline{};
        TimerId id{0U};
    };

    struct TimerQueueEarlier final {
        bool operator()(const TimerQueueEntry &left, const TimerQueueEntry &right) const noexcept
        {
            return left.deadline > right.deadline;
        }
    };

    core::StatusCode run_once_impl(int timeout_ms) noexcept;
    int wait_timeout_ms(int requested_timeout_ms) const noexcept;
    void dispatch_events(std::size_t event_count) noexcept;
    void dispatch_timers() noexcept;
    void detach_all_events() noexcept;

    int epoll_fd_{-1};
    core::StatusCode initialization_status_{core::StatusCode::Ok};
    bool running_{false};
    bool stopped_{false};
    std::unordered_set<Event *> registered_events_;
    std::unordered_map<TimerId, Timer> timers_;
    std::priority_queue<TimerQueueEntry, std::vector<TimerQueueEntry>, TimerQueueEarlier> timer_queue_;
    TimerId next_timer_id_{1U};
};

} // namespace skan::io

#endif // SKAN_IO_IO_ENGINE_HPP
