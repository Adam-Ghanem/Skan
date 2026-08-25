#include "io/io_engine.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <new>
#include <stdexcept>
#include <sys/epoll.h>
#include <unistd.h>
#include <utility>

#include "core/log.hpp"

namespace skan::io {
namespace {

constexpr std::size_t kMaxEventsPerWait = 64U;

std::uint32_t to_native_mask(EventMask mask) noexcept
{
    std::uint32_t native_mask = 0U;
    if (has_event(mask, EventMask::Read)) {
        native_mask |= static_cast<std::uint32_t>(EPOLLIN);
    }
    if (has_event(mask, EventMask::Write)) {
        native_mask |= static_cast<std::uint32_t>(EPOLLOUT);
    }
    if (has_event(mask, EventMask::Error)) {
        native_mask |= static_cast<std::uint32_t>(EPOLLERR);
    }
    if (has_event(mask, EventMask::Hangup)) {
        native_mask |= static_cast<std::uint32_t>(EPOLLHUP);
    }
    return native_mask;
}

EventMask from_native_mask(std::uint32_t native_mask) noexcept
{
    EventMask mask = EventMask::None;
    if ((native_mask & static_cast<std::uint32_t>(EPOLLIN)) != 0U) {
        mask = mask | EventMask::Read;
    }
    if ((native_mask & static_cast<std::uint32_t>(EPOLLOUT)) != 0U) {
        mask = mask | EventMask::Write;
    }
    if ((native_mask & static_cast<std::uint32_t>(EPOLLERR)) != 0U) {
        mask = mask | EventMask::Error;
    }
    if ((native_mask & static_cast<std::uint32_t>(EPOLLHUP)) != 0U) {
        mask = mask | EventMask::Hangup;
    }
    return mask;
}

core::StatusCode system_error(const char *operation)
{
    skan::log::error("{} failed: {}", operation, std::strerror(errno));
    return core::StatusCode::IoError;
}

} // namespace

IOEngine::IOEngine() noexcept
{
    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        initialization_status_ = system_error("epoll_create1");
    }
}

IOEngine::~IOEngine() noexcept
{
    (void)shutdown();
}

core::StatusCode IOEngine::initialization_status() const noexcept
{
    return initialization_status_;
}

core::StatusCode IOEngine::add(Event &event) noexcept
{
    if (initialization_status_ != core::StatusCode::Ok) {
        return initialization_status_;
    }
    if (epoll_fd_ < 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (event.file_descriptor() < 0 || event.mask() == EventMask::None || !event.callback_) {
        return core::StatusCode::InvalidArgument;
    }
    if (event.registered_ || event.owner_ != nullptr) {
        return core::StatusCode::InvalidArgument;
    }
    if (next_event_token_ == 0U) {
        return core::StatusCode::MemoryError;
    }
    const std::uint64_t event_token = next_event_token_++;

    epoll_event native_event{};
    native_event.events = to_native_mask(event.mask());
    native_event.data.u64 = event_token;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, event.file_descriptor(), &native_event) < 0) {
        return system_error("epoll_ctl ADD");
    }

    try {
        const auto token_insertion = event_tokens_.emplace(event_token, &event);
        if (!token_insertion.second) {
            (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, event.file_descriptor(), nullptr);
            return core::StatusCode::InternalError;
        }
        try {
            registered_events_.insert(&event);
        } catch (const std::bad_alloc &) {
            event_tokens_.erase(event_token);
            throw;
        }
    } catch (const std::bad_alloc &) {
        (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, event.file_descriptor(), nullptr);
        return core::StatusCode::MemoryError;
    }

    event.registration_token_ = event_token;
    event.registered_ = true;
    event.owner_ = this;
    skan::log::debug("registered fd {}", event.file_descriptor());
    return core::StatusCode::Ok;
}

core::StatusCode IOEngine::modify(Event &event) noexcept
{
    if (initialization_status_ != core::StatusCode::Ok) {
        return initialization_status_;
    }
    if (epoll_fd_ < 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (!event.registered_ || event.owner_ != this || event.mask() == EventMask::None || !event.callback_) {
        return core::StatusCode::InvalidArgument;
    }

    epoll_event native_event{};
    native_event.events = to_native_mask(event.mask());
    native_event.data.u64 = event.registration_token_;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, event.file_descriptor(), &native_event) < 0) {
        return system_error("epoll_ctl MOD");
    }

    skan::log::debug("modified fd {}", event.file_descriptor());
    return core::StatusCode::Ok;
}

core::StatusCode IOEngine::remove(Event &event) noexcept
{
    if (initialization_status_ != core::StatusCode::Ok) {
        return initialization_status_;
    }
    if (epoll_fd_ < 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (!event.registered_ || event.owner_ != this) {
        return core::StatusCode::NotFound;
    }

    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, event.file_descriptor(), nullptr) < 0 && errno != ENOENT) {
        return system_error("epoll_ctl DEL");
    }

    registered_events_.erase(&event);
    event_tokens_.erase(event.registration_token_);
    event.registration_token_ = 0U;
    event.registered_ = false;
    event.owner_ = nullptr;
    event.ready_mask_ = EventMask::None;
    skan::log::debug("unregistered fd {}", event.file_descriptor());
    return core::StatusCode::Ok;
}

core::StatusCode IOEngine::run() noexcept
{
    if (initialization_status_ != core::StatusCode::Ok) {
        return initialization_status_;
    }
    if (epoll_fd_ < 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (running_) {
        return core::StatusCode::InvalidArgument;
    }

    stopped_ = false;
    running_ = true;
    core::StatusCode result = core::StatusCode::Ok;
    while (!stopped_) {
        if (registered_events_.empty() && timers_.empty()) {
            break;
        }
        result = run_once_impl(-1);
        if (result != core::StatusCode::Ok) {
            break;
        }
    }
    running_ = false;
    return result;
}

core::StatusCode IOEngine::run_once(int timeout_ms) noexcept
{
    if (initialization_status_ != core::StatusCode::Ok) {
        return initialization_status_;
    }
    if (epoll_fd_ < 0) {
        return core::StatusCode::InvalidArgument;
    }
    if (running_) {
        return core::StatusCode::InvalidArgument;
    }
    stopped_ = false;
    running_ = true;
    const core::StatusCode result = run_once_impl(timeout_ms);
    running_ = false;
    stopped_ = false;
    return result;

}

void IOEngine::stop() noexcept
{
    stopped_ = true;
}

core::StatusCode IOEngine::shutdown() noexcept
{
    detach_all_events();
    timers_.clear();
    while (!timer_queue_.empty()) {
        timer_queue_.pop();
    }

    if (epoll_fd_ < 0) {
        running_ = false;
        stopped_ = true;
        return core::StatusCode::Ok;
    }

    const int descriptor = epoll_fd_;
    epoll_fd_ = -1;
    running_ = false;
    stopped_ = true;
    if (::close(descriptor) < 0) {
        return system_error("close epoll descriptor");
    }
    return core::StatusCode::Ok;
}

bool IOEngine::running() const noexcept
{
    return running_;
}

TimerId IOEngine::schedule(TimerDuration delay, TimerCallback callback)
{
    if (epoll_fd_ < 0 || !callback) {
        return 0U;
    }
    if (next_timer_id_ == 0U) {
        return 0U;
    }

    const TimerId timer_id = next_timer_id_++;
    Timer timer{timer_id, TimerClock::now() + std::max(delay, TimerDuration::zero()), std::move(callback), false};
    try {
        timers_.emplace(timer_id, timer);
        timer_queue_.push(TimerQueueEntry{timer.deadline, timer_id});
    } catch (const std::bad_alloc &) {
        timers_.erase(timer_id);
        return 0U;
    }
    return timer_id;
}

core::StatusCode IOEngine::cancel(TimerId timer_id) noexcept
{
    if (timer_id == 0U) {
        return core::StatusCode::Ok;
    }
    const auto iterator = timers_.find(timer_id);
    if (iterator != timers_.end()) {
        iterator->second.cancelled = true;
        timers_.erase(iterator);
    }
    return core::StatusCode::Ok;
}

core::StatusCode IOEngine::set_nonblocking(int file_descriptor) noexcept
{
    if (file_descriptor < 0) {
        return core::StatusCode::InvalidArgument;
    }

    const int current_flags = ::fcntl(file_descriptor, F_GETFL, 0);
    if (current_flags < 0) {
        return system_error("fcntl F_GETFL");
    }
    if (::fcntl(file_descriptor, F_SETFL, current_flags | O_NONBLOCK) < 0) {
        return system_error("fcntl F_SETFL");
    }
    return core::StatusCode::Ok;
}

core::StatusCode IOEngine::run_once_impl(int timeout_ms) noexcept
{
    if (registered_events_.empty() && timers_.empty()) {
        return core::StatusCode::Ok;
    }

    while (!timer_queue_.empty()) {
        const TimerQueueEntry &entry = timer_queue_.top();
        if (timers_.find(entry.id) != timers_.end()) {
            break;
        }
        timer_queue_.pop();
    }

    const int wait_timeout = wait_timeout_ms(timeout_ms);
    std::array<epoll_event, kMaxEventsPerWait> native_events{};
    const int event_count = ::epoll_wait(epoll_fd_, native_events.data(), static_cast<int>(native_events.size()), wait_timeout);
    if (event_count < 0) {
        if (errno == EINTR) {
            dispatch_timers();
            return core::StatusCode::Ok;
        }
        return system_error("epoll_wait");
    }

    for (int index = 0; index < event_count; ++index) {
        const std::uint64_t event_token = native_events[static_cast<std::size_t>(index)].data.u64;
        const auto event_iterator = event_tokens_.find(event_token);
        if (event_iterator == event_tokens_.end()) {
            continue;
        }
        Event *event = event_iterator->second;
        if (event == nullptr || !event->registered_ || event->owner_ != this ||
            event->registration_token_ != event_token) {
            continue;
        }

        event->ready_mask_ = from_native_mask(native_events[static_cast<std::size_t>(index)].events);
        skan::log::debug("dispatching fd {}", event->file_descriptor());
        try {
            event->callback_(*event);
        } catch (const std::exception &exception) {
            skan::log::error("event callback threw: {}", exception.what());
        } catch (...) {
            skan::log::error("event callback threw an unknown exception");
        }
        const auto active_event_iterator = event_tokens_.find(event_token);
        if (active_event_iterator != event_tokens_.end() && active_event_iterator->second == event) {
            active_event_iterator->second->ready_mask_ = EventMask::None;
        }
        if (stopped_) {
            break;
        }
    }

    dispatch_timers();
    return core::StatusCode::Ok;
}

int IOEngine::wait_timeout_ms(int requested_timeout_ms) const noexcept
{
    int timeout = requested_timeout_ms < 0 ? -1 : requested_timeout_ms;
    if (timer_queue_.empty()) {
        return timeout;
    }

    const auto iterator = timers_.find(timer_queue_.top().id);
    if (iterator == timers_.end()) {
        return timeout;
    }

    const TimerClock::time_point now = TimerClock::now();
    int timer_timeout = 0;
    if (iterator->second.deadline > now) {
        const auto remaining = iterator->second.deadline - now;
        auto rounded_up = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
        if (rounded_up < remaining) {
            rounded_up += std::chrono::milliseconds{1};
        }
        auto remaining_count = rounded_up.count();
        using DurationCount = decltype(remaining_count);
        const DurationCount maximum = static_cast<DurationCount>(std::numeric_limits<int>::max());
        timer_timeout = remaining_count >= maximum ? std::numeric_limits<int>::max() : static_cast<int>(remaining_count);
    }

    if (timeout < 0) {
        return timer_timeout;
    }
    return std::min(timeout, timer_timeout);
}

void IOEngine::dispatch_timers() noexcept
{
    while (!stopped_ && !timer_queue_.empty()) {
        const TimerQueueEntry entry = timer_queue_.top();
        if (entry.deadline > TimerClock::now()) {
            break;
        }
        timer_queue_.pop();

        const auto iterator = timers_.find(entry.id);
        if (iterator == timers_.end() || iterator->second.cancelled) {
            continue;
        }

        TimerCallback callback = std::move(iterator->second.callback);
        timers_.erase(iterator);
        skan::log::debug("dispatching timer {}", entry.id);
        try {
            callback();
        } catch (const std::exception &exception) {
            skan::log::error("timer callback threw: {}", exception.what());
        } catch (...) {
            skan::log::error("timer callback threw an unknown exception");
        }
    }
}

void IOEngine::detach_all_events() noexcept
{
    for (Event *event : registered_events_) {
        if (event != nullptr) {
            event_tokens_.erase(event->registration_token_);
            event->registration_token_ = 0U;
            event->registered_ = false;
            event->owner_ = nullptr;
            event->ready_mask_ = EventMask::None;
        }
    }
    registered_events_.clear();
}

} // namespace skan::io
