#include <cassert>
#include <cstring>

#include "c_api/status.h"
#include "core/status.hpp"

int main()
{
    using skan::core::StatusCode;
    using skan::core::status_to_string;

    assert(std::strcmp(status_to_string(StatusCode::Ok), "ok") == 0);
    assert(std::strcmp(status_to_string(StatusCode::InvalidArgument), "invalid argument") == 0);
    assert(std::strcmp(status_to_string(StatusCode::MemoryError), "memory error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::IoError), "I/O error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::PermissionDenied), "permission denied") == 0);
    assert(std::strcmp(status_to_string(StatusCode::ParseError), "parse error") == 0);
    assert(std::strcmp(status_to_string(StatusCode::NotFound), "not found") == 0);
    assert(std::strcmp(status_to_string(StatusCode::InternalError), "internal error") == 0);
    assert(status_to_string(static_cast<StatusCode>(999)) != nullptr);
    assert(std::strcmp(status_to_string(static_cast<StatusCode>(999)), "unknown status") == 0);

    assert(std::strcmp(skan_c_status_string(SKAN_C_STATUS_OK), "ok") == 0);
    assert(std::strcmp(skan_c_status_string(SKAN_C_STATUS_INTERNAL_ERROR), "internal error") == 0);

    return 0;
}
