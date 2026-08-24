#include "io/event.hpp"

#include <utility>

namespace skan::io {

Event::Event(int file_descriptor, EventMask mask, EventCallback callback, void *context)
    : file_descriptor_(file_descriptor),
      mask_(mask),
      callback_(std::move(callback)),
      context_(context)
{
}

int Event::file_descriptor() const noexcept
{
    return file_descriptor_;
}

EventMask Event::mask() const noexcept
{
    return mask_;
}

void Event::set_mask(EventMask mask) noexcept
{
    mask_ = mask;
}

EventMask Event::ready_mask() const noexcept
{
    return ready_mask_;
}

void *Event::context() const noexcept
{
    return context_;
}

bool Event::registered() const noexcept
{
    return registered_;
}

} // namespace skan::io
