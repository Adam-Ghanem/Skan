#ifndef SKAN_CORE_ERRORS_H
#define SKAN_CORE_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SKAN_OK = 0,
    SKAN_ERR_INVALID_ARG,
    SKAN_ERR_MEMORY,
    SKAN_ERR_IO,
    SKAN_ERR_PERMISSION,
    SKAN_ERR_PARSE,
    SKAN_ERR_NOT_FOUND,
    SKAN_ERR_INTERNAL
} skan_status_t;

/** Return a stable human-readable label for a status value. */
const char *skan_status_string(skan_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* SKAN_CORE_ERRORS_H */
