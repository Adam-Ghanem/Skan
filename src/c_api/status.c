#include "c_api/status.h"

const char *skan_c_status_string(skan_c_status_code_t status)
{
    switch (status) {
    case SKAN_C_STATUS_OK:
        return "ok";
    case SKAN_C_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case SKAN_C_STATUS_MEMORY_ERROR:
        return "memory error";
    case SKAN_C_STATUS_IO_ERROR:
        return "I/O error";
    case SKAN_C_STATUS_PERMISSION_DENIED:
        return "permission denied";
    case SKAN_C_STATUS_PARSE_ERROR:
        return "parse error";
    case SKAN_C_STATUS_NOT_FOUND:
        return "not found";
    case SKAN_C_STATUS_INTERNAL_ERROR:
        return "internal error";
    case SKAN_C_STATUS_RESOURCE_EXHAUSTED:
        return "resource exhausted";
    default:
        return "unknown status";
    }
}
