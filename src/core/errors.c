#include "core/errors.h"

const char *skan_status_string(skan_status_t status)
{
    switch (status) {
    case SKAN_OK:
        return "ok";
    case SKAN_ERR_INVALID_ARG:
        return "invalid argument";
    case SKAN_ERR_MEMORY:
        return "memory error";
    case SKAN_ERR_IO:
        return "I/O error";
    case SKAN_ERR_PERMISSION:
        return "permission denied";
    case SKAN_ERR_PARSE:
        return "parse error";
    case SKAN_ERR_NOT_FOUND:
        return "not found";
    case SKAN_ERR_INTERNAL:
        return "internal error";
    default:
        return "unknown status";
    }
}
