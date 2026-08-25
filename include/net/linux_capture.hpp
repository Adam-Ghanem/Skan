#ifndef SKAN_NET_LINUX_CAPTURE_HPP
#define SKAN_NET_LINUX_CAPTURE_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#include "net/capture.hpp"
#include "net/unique_fd.hpp"

namespace skan::net {

class LinuxCapture final : public PacketCapture {
public:
    LinuxCapture() noexcept = default;
    ~LinuxCapture() noexcept override;

    CaptureResult open(const CaptureConfig &config) override;
    CaptureResult receive(std::span<std::uint8_t> buffer) override;
    void close() noexcept override;
    bool is_open() const noexcept override;
    int file_descriptor() const noexcept override;

    const CaptureConfig &configuration() const noexcept;

private:
    detail::UniqueFd file_descriptor_;
    CaptureConfig configuration_;
};

} // namespace skan::net

#endif // SKAN_NET_LINUX_CAPTURE_HPP
