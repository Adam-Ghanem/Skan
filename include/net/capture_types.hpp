#ifndef SKAN_NET_CAPTURE_TYPES_HPP
#define SKAN_NET_CAPTURE_TYPES_HPP

#include <cstddef>
#include <string>
#include <string_view>

namespace skan::net {

enum class CaptureStatus {
    Success,
    InvalidConfiguration,
    InterfaceNotFound,
    PermissionDenied,
    NotSupported,
    NotOpen,
    WouldBlock,
    Empty,
    BufferTooSmall,
    ReceiveFailed,
    Closed,
    MalformedFrame,
    OversizedFrame,
    SystemError
};

const char *capture_status_name(CaptureStatus status) noexcept;

struct CaptureConfig final {
    std::string interface_name;
    std::size_t max_frame_size{65535U};
    bool nonblocking{true};
};

struct CaptureResult final {
    CaptureStatus status{CaptureStatus::Success};
    std::size_t bytes_received{0U};
    int system_error{0};
    std::string message;

    bool success() const noexcept { return status == CaptureStatus::Success; }
};

CaptureResult capture_success(std::size_t bytes_received);
CaptureResult capture_failure(CaptureStatus status, int system_error, std::string_view message);

} // namespace skan::net

#endif // SKAN_NET_CAPTURE_TYPES_HPP
