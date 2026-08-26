#include "net/interface_types.hpp"

namespace skan::net {

const char *capability_state_name(CapabilityState state) noexcept
{
    switch (state) {
    case CapabilityState::Available:
        return "AVAILABLE";
    case CapabilityState::Unavailable:
        return "UNAVAILABLE";
    case CapabilityState::Unknown:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

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
    case InterfaceStatus::RoutingUnavailable:
        return "routing-unavailable";
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
