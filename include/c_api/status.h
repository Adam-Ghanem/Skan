#ifndef SKAN_C_API_STATUS_H
#define SKAN_C_API_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SKAN_C_STATUS_OK = 0,
    SKAN_C_STATUS_INVALID_ARGUMENT,
    SKAN_C_STATUS_MEMORY_ERROR,
    SKAN_C_STATUS_IO_ERROR,
    SKAN_C_STATUS_PERMISSION_DENIED,
    SKAN_C_STATUS_PARSE_ERROR,
    SKAN_C_STATUS_NOT_FOUND,
    SKAN_C_STATUS_INTERNAL_ERROR,
    SKAN_C_STATUS_RESOURCE_EXHAUSTED
} skan_c_status_code_t;

/** Return a non-null, allocation-free label for a C status code. */
const char *skan_c_status_string(skan_c_status_code_t status);

#ifdef __cplusplus
}
#endif

#endif /* SKAN_C_API_STATUS_H */
