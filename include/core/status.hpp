#ifndef SKAN_CORE_STATUS_HPP
#define SKAN_CORE_STATUS_HPP

namespace skan::core {

enum class StatusCode {
    Ok = 0,
    InvalidArgument,
    MemoryError,
    IoError,
    PermissionDenied,
    ParseError,
    NotFound,
    InternalError,
    ResourceExhausted
};

enum class ExitCode : int {
    Success = 0,
    Usage = 1,
    Permission = 2,
    Runtime = 3,
    Partial = 4
};

/** Return a non-null, allocation-free label for a status code. */
const char *status_to_string(StatusCode status) noexcept;

/** Map an internal status to the stable process exit taxonomy. */
ExitCode status_to_exit_code(StatusCode status) noexcept;

constexpr int exit_code_value(ExitCode code) noexcept
{
    return static_cast<int>(code);
}

} // namespace skan::core

#endif // SKAN_CORE_STATUS_HPP