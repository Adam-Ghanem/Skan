#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "net/capture.hpp"

int main()
{
    skan::net::RecordingCapture capture;
    std::vector<std::uint8_t> buffer(8U, 0U);
    assert(capture.receive(std::span<std::uint8_t>{buffer}).status == skan::net::CaptureStatus::NotOpen);
    assert(capture.open(skan::net::CaptureConfig{"unit-test0", 8U, true}).success());
    assert(capture.is_open());
    assert(capture.receive(std::span<std::uint8_t>{buffer}).status == skan::net::CaptureStatus::Empty);

    capture.enqueue({0x01U, 0x02U, 0x03U});
    assert(capture.receive(std::span<std::uint8_t>{}).status == skan::net::CaptureStatus::BufferTooSmall);
    assert(capture.pending_count() == 1U);
    assert(capture.receive(std::span<std::uint8_t>{buffer}).success());
    assert(buffer[0] == 0x01U && buffer[2] == 0x03U);

    capture.enqueue({0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U});
    std::vector<std::uint8_t> small_buffer(2U, 0U);
    const skan::net::CaptureResult too_small = capture.receive(std::span<std::uint8_t>{small_buffer});
    assert(too_small.status == skan::net::CaptureStatus::BufferTooSmall);
    assert(too_small.bytes_received == 6U);
    assert(capture.pending_count() == 1U);
    assert(capture.receive(std::span<std::uint8_t>{buffer}).success());

    capture.enqueue({0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U});
    const skan::net::CaptureResult oversized = capture.receive(std::span<std::uint8_t>{buffer});
    assert(oversized.status == skan::net::CaptureStatus::OversizedFrame);
    assert(oversized.bytes_received == 9U);

    capture.close();
    capture.close();
    assert(!capture.is_open());
    assert(capture.open(skan::net::CaptureConfig{"unit-test0", 0U, true}).status ==
           skan::net::CaptureStatus::InvalidConfiguration);
    return 0;
}
