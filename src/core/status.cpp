#include "core/status.hpp"

namespace skan::core {

const char *status_to_string(StatusCode status) noexcept
{
    switch (status) {
    case StatusCode::Ok:
        return "ok";
    case StatusCode::InvalidArgument:
        return "invalid argument";
    case StatusCode::MemoryError:
        return "memory error";
    case StatusCode::IoError:
        return "I/O error";
    case StatusCode::PermissionDenied:
        return "permission denied";
    case StatusCode::ParseError:
        return "parse error";
    case StatusCode::NotFound:
        return "not found";
    case StatusCode::InternalError:
        return "internal error";
    default:
        return "unknown status";
    }
}

} // namespace skan::core
