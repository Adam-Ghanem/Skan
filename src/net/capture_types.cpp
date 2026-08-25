#include "net/capture_types.hpp"

namespace skan::net {

const char *capture_status_name(CaptureStatus status) noexcept
{
    switch (status) {
    case CaptureStatus::Success:
        return "success";
    case CaptureStatus::InvalidConfiguration:
        return "invalid-configuration";
    case CaptureStatus::InterfaceNotFound:
        return "interface-not-found";
    case CaptureStatus::PermissionDenied:
        return "permission-denied";
    case CaptureStatus::NotSupported:
        return "not-supported";
    case CaptureStatus::NotOpen:
        return "not-open";
    case CaptureStatus::WouldBlock:
        return "would-block";
    case CaptureStatus::Empty:
        return "empty";
    case CaptureStatus::BufferTooSmall:
        return "buffer-too-small";
    case CaptureStatus::ReceiveFailed:
        return "receive-failed";
    case CaptureStatus::Closed:
        return "closed";
    case CaptureStatus::MalformedFrame:
        return "malformed-frame";
    case CaptureStatus::OversizedFrame:
        return "oversized-frame";
    case CaptureStatus::SystemError:
        return "system-error";
    }
    return "unknown";
}

CaptureResult capture_success(std::size_t bytes_received)
{
    return CaptureResult{CaptureStatus::Success, bytes_received, 0, {}};
}

CaptureResult capture_failure(CaptureStatus status, int system_error, std::string_view message)
{
    return CaptureResult{status, 0U, system_error, std::string{message}};
}

} // namespace skan::net
