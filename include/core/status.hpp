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

/** Return a non-null, allocation-free label for a status code. */
const char *status_to_string(StatusCode status) noexcept;

} // namespace skan::core

#endif // SKAN_CORE_STATUS_HPP
