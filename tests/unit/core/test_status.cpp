#include <cassert>
#include <cstring>

#include "c_api/status.h"
#include "core/status.hpp"

int main()
{
    using skan::core::ExitCode;
    using skan::core::StatusCode;
    using skan::core::exit_code_value;
    using skan::core::status_to_exit_code;
    using skan::core::status_to_string;

    assert(std::strcmp(status_to_string(StatusCode::Ok), "ok") == 0);
    assert(std::strcmp(status_to_string(StatusCode::InvalidArgument), "invalid argument") == 0);
    assert(std::strcmp(status_to_string(StatusCode::MemoryError), "memory error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::IoError), "I/O error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::PermissionDenied), "permission denied") == 0);
    assert(std::strcmp(status_to_string(StatusCode::ParseError), "parse error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::NotFound), "not found") == 0);
    assert(std::strcmp(status_to_string(StatusCode::InternalError), "internal error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::ResourceExhausted), "resource exhausted") == 0);
    assert(status_to_string(static_cast<StatusCode>(999)) != nullptr);
    assert(std::strcmp(status_to_string(static_cast<StatusCode>(999)), "unknown status") == 0);

    assert(exit_code_value(ExitCode::Success) == 0);
    assert(exit_code_value(ExitCode::Usage) == 1);
    assert(exit_code_value(ExitCode::Permission) == 2);
    assert(exit_code_value(ExitCode::Runtime) == 3);
    assert(exit_code_value(ExitCode::Partial) == 4);

    assert(status_to_exit_code(StatusCode::Ok) == ExitCode::Success);
    assert(status_to_exit_code(StatusCode::InvalidArgument) == ExitCode::Usage);
    assert(status_to_exit_code(StatusCode::ParseError) == ExitCode::Runtime);
    assert(status_to_exit_code(StatusCode::PermissionDenied) == ExitCode::Permission);
    assert(status_to_exit_code(StatusCode::MemoryError) == ExitCode::Runtime);
    assert(status_to_exit_code(StatusCode::IoError) == ExitCode::Runtime);
    assert(status_to_exit_code(StatusCode::NotFound) == ExitCode::Runtime);
    assert(status_to_exit_code(StatusCode::InternalError) == ExitCode::Runtime);
    assert(status_to_exit_code(StatusCode::ResourceExhausted) == ExitCode::Runtime);
    assert(status_to_exit_code(static_cast<StatusCode>(999)) == ExitCode::Runtime);

    assert(std::strcmp(skan_c_status_string(SKAN_C_STATUS_OK), "ok") == 0);
    assert(std::strcmp(skan_c_status_string(SKAN_C_STATUS_INTERNAL_ERROR), "internal error") == 0);
    assert(std::strcmp(skan_c_status_string(SKAN_C_STATUS_RESOURCE_EXHAUSTED), "resource exhausted") == 0);

    return 0;
}
