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

const char *preflight_category_name(PreflightCategory category) noexcept
{
    switch (category) {
    case PreflightCategory::Ready:
        return "READY";
    case PreflightCategory::InvalidInterface:
        return "INVALID_INTERFACE";
    case PreflightCategory::InterfaceDown:
        return "INTERFACE_DOWN";
    case PreflightCategory::NoSourceAddress:
        return "NO_SOURCE_ADDRESS";
    case PreflightCategory::NoRoute:
        return "NO_ROUTE";
    case PreflightCategory::CapabilityUnavailable:
        return "CAPABILITY_UNAVAILABLE";
    case PreflightCategory::CaptureUnavailable:
        return "CAPTURE_UNAVAILABLE";
    case PreflightCategory::InjectionUnavailable:
        return "INJECTION_UNAVAILABLE";
    case PreflightCategory::UnsupportedFamily:
        return "UNSUPPORTED_FAMILY";
    case PreflightCategory::MtuUnavailable:
        return "MTU_UNAVAILABLE";
    }
    return "CAPABILITY_UNAVAILABLE";
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
