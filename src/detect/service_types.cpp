#include "detect/service_types.hpp"

namespace skan::detect {

const char *detection_state_name(DetectionState state) noexcept
{
    switch (state) {
    case DetectionState::Detected:
        return "DETECTED";
    case DetectionState::Unknown:
        return "UNKNOWN";
    case DetectionState::Timeout:
        return "TIMEOUT";
    case DetectionState::ConnectionClosed:
        return "CONNECTION_CLOSED";
    case DetectionState::ResponseTooLarge:
        return "RESPONSE_TOO_LARGE";
    case DetectionState::Unauthorized:
        return "UNAUTHORIZED";
    case DetectionState::InvalidTarget:
        return "INVALID_TARGET";
    case DetectionState::Error:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

const char *detection_error_name(DetectionError error) noexcept
{
    switch (error) {
    case DetectionError::None:
        return "NONE";
    case DetectionError::Timeout:
        return "TIMEOUT";
    case DetectionError::ConnectionClosed:
        return "CONNECTION_CLOSED";
    case DetectionError::ResponseTooLarge:
        return "RESPONSE_TOO_LARGE";
    case DetectionError::UnauthorizedTarget:
        return "UNAUTHORIZED_TARGET";
    case DetectionError::InvalidTarget:
        return "INVALID_TARGET";
    case DetectionError::TransportFailure:
        return "TRANSPORT_FAILURE";
    case DetectionError::MalformedResponse:
        return "MALFORMED_RESPONSE";
    case DetectionError::NoMatch:
        return "NO_MATCH";
    case DetectionError::UnsupportedProtocol:
        return "UNSUPPORTED_PROTOCOL";
    case DetectionError::InternalError:
        return "INTERNAL_ERROR";
    default:
        return "INTERNAL_ERROR";
    }
}

const char *detection_method_name(DetectionMethod method) noexcept
{
    switch (method) {
    case DetectionMethod::Banner:
        return "banner";
    case DetectionMethod::Probe:
        return "probe";
    case DetectionMethod::Unknown:
    default:
        return "unknown";
    }
}

bool service_result_less(const ServiceResult &left, const ServiceResult &right) noexcept
{
    if (left.target != right.target) {
        return left.target < right.target;
    }
    if (left.port.number != right.port.number) {
        return left.port.number < right.port.number;
    }
    if (left.probe_name != right.probe_name) {
        return left.probe_name < right.probe_name;
    }
    return static_cast<unsigned int>(left.state) < static_cast<unsigned int>(right.state);
}

} // namespace skan::detect
