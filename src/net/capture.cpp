#include "net/capture.hpp"

#include <algorithm>
#include <utility>

namespace skan::net {

RecordingCapture::RecordingCapture(std::vector<std::vector<std::uint8_t>> frames)
{
    for (std::vector<std::uint8_t> &frame : frames) {
        frames_.push_back(std::move(frame));
    }
}

CaptureResult RecordingCapture::open(const CaptureConfig &config)
{
    if (config.max_frame_size == 0U) {
        return capture_failure(CaptureStatus::InvalidConfiguration, 0, "maximum frame size must be positive");
    }
    max_frame_size_ = config.max_frame_size;
    open_ = true;
    return capture_success(0U);
}

CaptureResult RecordingCapture::receive(std::span<std::uint8_t> buffer)
{
    if (!open_) {
        return capture_failure(CaptureStatus::NotOpen, 0, "capture is not open");
    }
    if (buffer.empty()) {
        return capture_failure(CaptureStatus::BufferTooSmall, 0, "receive buffer is empty");
    }
    if (frames_.empty()) {
        return capture_failure(CaptureStatus::Empty, 0, "no captured frame is queued");
    }
    const std::vector<std::uint8_t> &frame = frames_.front();
    if (frame.size() > max_frame_size_) {
        const std::size_t size = frame.size();
        frames_.pop_front();
        CaptureResult result = capture_failure(CaptureStatus::OversizedFrame, 0, "queued frame exceeds configured limit");
        result.bytes_received = size;
        return result;
    }
    if (frame.size() > buffer.size()) {
        CaptureResult result = capture_failure(CaptureStatus::BufferTooSmall, 0, "receive buffer is too small");
        result.bytes_received = frame.size();
        return result;
    }
    std::copy(frame.begin(), frame.end(), buffer.begin());
    const std::size_t size = frame.size();
    frames_.pop_front();
    return capture_success(size);
}

void RecordingCapture::close() noexcept
{
    open_ = false;
}

bool RecordingCapture::is_open() const noexcept
{
    return open_;
}

void RecordingCapture::enqueue(std::vector<std::uint8_t> frame)
{
    frames_.push_back(std::move(frame));
}

std::size_t RecordingCapture::pending_count() const noexcept
{
    return frames_.size();
}

void RecordingCapture::clear() noexcept
{
    frames_.clear();
}

} // namespace skan::net
