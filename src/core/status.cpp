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
    case StatusCode::ResourceExhausted:
        return "resource exhausted";
    default:
        return "unknown status";
    }
}

ExitCode status_to_exit_code(StatusCode status) noexcept
{
    switch (status) {
    case StatusCode::Ok:
        return ExitCode::Success;
    case StatusCode::InvalidArgument:
        return ExitCode::Usage;
    case StatusCode::PermissionDenied:
        return ExitCode::Permission;
    case StatusCode::MemoryError:
    case StatusCode::IoError:
    case StatusCode::ParseError:
    case StatusCode::NotFound:
    case StatusCode::InternalError:
    case StatusCode::ResourceExhausted:
    default:
        return ExitCode::Runtime;
    }
}

} // namespace skan::core
