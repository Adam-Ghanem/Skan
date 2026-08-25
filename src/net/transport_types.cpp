#include "net/transport_types.hpp"

namespace skan::net {

const char *transport_status_name(TransportStatus status) noexcept
{
    switch (status) {
    case TransportStatus::Success:
        return "success";
    case TransportStatus::InvalidConfiguration:
        return "invalid-configuration";
    case TransportStatus::InterfaceNotFound:
        return "interface-not-found";
    case TransportStatus::PermissionDenied:
        return "permission-denied";
    case TransportStatus::NotSupported:
        return "not-supported";
    case TransportStatus::NotOpen:
        return "not-open";
    case TransportStatus::SendFailed:
        return "send-failed";
    case TransportStatus::CaptureFailed:
        return "capture-failed";
    case TransportStatus::Closed:
        return "closed";
    case TransportStatus::SystemError:
        return "system-error";
    }
    return "unknown";
}

TransportResult transport_success()
{
    return TransportResult{TransportStatus::Success, 0, {}};
}

TransportResult transport_failure(TransportStatus status, int system_error, std::string_view message)
{
    return TransportResult{status, system_error, std::string{message}};
}

} // namespace skan::net
