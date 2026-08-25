#include "net/interface_types.hpp"

namespace skan::net {

const char *interface_status_name(InterfaceStatus status) noexcept
{
    switch (status) {
    case InterfaceStatus::Success:
        return "success";
    case InterfaceStatus::InvalidName:
        return "invalid-name";
    case InterfaceStatus::EnumerationFailed:
        return "enumeration-failed";
    case InterfaceStatus::InterfaceNotFound:
        return "interface-not-found";
    case InterfaceStatus::PermissionDenied:
        return "permission-denied";
    case InterfaceStatus::NotSupported:
        return "not-supported";
    case InterfaceStatus::SystemError:
        return "system-error";
    }
    return "unknown";
}

} // namespace skan::net
