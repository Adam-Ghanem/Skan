#ifndef SKAN_NET_CAPTURE_HPP
#define SKAN_NET_CAPTURE_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <vector>

#include "net/capture_types.hpp"

namespace skan::net {

class PacketCapture {
public:
    virtual ~PacketCapture() = default;

    virtual CaptureResult open(const CaptureConfig &config) = 0;
    virtual CaptureResult receive(std::span<std::uint8_t> buffer) = 0;
    virtual void close() noexcept = 0;
    virtual bool is_open() const noexcept = 0;
    virtual int file_descriptor() const noexcept { return -1; }
};

/** Deterministic, privilege-free capture source used by receiver tests. */
class RecordingCapture final : public PacketCapture {
public:
    explicit RecordingCapture(std::vector<std::vector<std::uint8_t>> frames = {});

    CaptureResult open(const CaptureConfig &config) override;
    CaptureResult receive(std::span<std::uint8_t> buffer) override;
    void close() noexcept override;
    bool is_open() const noexcept override;

    void enqueue(std::vector<std::uint8_t> frame);
    std::size_t pending_count() const noexcept;
    void clear() noexcept;

private:
    bool open_{false};
    std::size_t max_frame_size_{65535U};
    std::deque<std::vector<std::uint8_t>> frames_;
};

} // namespace skan::net

#endif // SKAN_NET_CAPTURE_HPP
