#include "net/transport.hpp"

#include <utility>

namespace skan::net {

TransportResult RecordingTransport::open(const TransportConfig &config)
{
    (void)config;
    open_ = true;
    return transport_success();
}

TransportResult RecordingTransport::send(std::span<const std::uint8_t> frame)
{
    if (!open_) {
        return transport_failure(TransportStatus::NotOpen, 0, "transport is not open");
    }
    frames_.emplace_back(frame.begin(), frame.end());
    return transport_success();
}

void RecordingTransport::close() noexcept
{
    open_ = false;
}

bool RecordingTransport::is_open() const noexcept
{
    return open_;
}

const std::vector<std::vector<std::uint8_t>> &RecordingTransport::frames() const noexcept
{
    return frames_;
}

std::size_t RecordingTransport::frame_count() const noexcept
{
    return frames_.size();
}

void RecordingTransport::clear_frames() noexcept
{
    frames_.clear();
}

TransportResult NullTransport::open(const TransportConfig &config)
{
    (void)config;
    open_ = true;
    return transport_success();
}

TransportResult NullTransport::send(std::span<const std::uint8_t> frame)
{
    if (!open_) {
        return transport_failure(TransportStatus::NotOpen, 0, "transport is not open");
    }
    (void)frame;
    ++send_count_;
    return transport_success();
}

void NullTransport::close() noexcept
{
    open_ = false;
}

bool NullTransport::is_open() const noexcept
{
    return open_;
}

std::size_t NullTransport::send_count() const noexcept
{
    return send_count_;
}

} // namespace skan::net
