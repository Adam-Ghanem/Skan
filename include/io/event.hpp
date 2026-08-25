#ifndef SKAN_IO_EVENT_HPP
#define SKAN_IO_EVENT_HPP

#include <cstdint>
#include <functional>

namespace skan::io {

enum class EventMask : unsigned int {
    None = 0U,
    Read = 1U << 0U,
    Write = 1U << 1U,
    Error = 1U << 2U,
    Hangup = 1U << 3U
};

constexpr EventMask operator|(EventMask left, EventMask right) noexcept
{
    return static_cast<EventMask>(static_cast<unsigned int>(left) | static_cast<unsigned int>(right));
}

constexpr EventMask operator&(EventMask left, EventMask right) noexcept
{
    return static_cast<EventMask>(static_cast<unsigned int>(left) & static_cast<unsigned int>(right));
}

constexpr bool has_event(EventMask mask, EventMask event) noexcept
{
    return (mask & event) != EventMask::None;
}

class Event;
using EventCallback = std::function<void(Event &)>;

/**
 * A logical file-descriptor event owned by its caller and registered with one IOEngine at a time.
 * The caller must keep the Event alive until it is removed or the engine is shut down.
 */
class Event final {
public:
    Event(int file_descriptor, EventMask mask, EventCallback callback, void *context = nullptr);
    ~Event() = default;

    Event(const Event &) = delete;
    Event &operator=(const Event &) = delete;
    Event(Event &&) = delete;
    Event &operator=(Event &&) = delete;

    int file_descriptor() const noexcept;
    EventMask mask() const noexcept;
    void set_mask(EventMask mask) noexcept;
    EventMask ready_mask() const noexcept;
    void *context() const noexcept;
    bool registered() const noexcept;

private:
    friend class IOEngine;

    int file_descriptor_;
    EventMask mask_;
    EventMask ready_mask_{EventMask::None};
    EventCallback callback_;
    void *context_;
    bool registered_{false};
    const void *owner_{nullptr};
    std::uint64_t registration_token_{0U};
};

} // namespace skan::io

#endif // SKAN_IO_EVENT_HPP
