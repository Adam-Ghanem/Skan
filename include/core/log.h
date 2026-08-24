#ifndef SKAN_CORE_LOG_H
#define SKAN_CORE_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SKAN_LOG_LEVEL_DEBUG = 0,
    SKAN_LOG_LEVEL_INFO,
    SKAN_LOG_LEVEL_WARN,
    SKAN_LOG_LEVEL_ERROR
} skan_log_level_t;

/** Log a DEBUG message to standard output. */
void skan_log_debug(const char *format, ...);

/** Log an INFO message to standard output. */
void skan_log_info(const char *format, ...);

/** Log a WARN message to standard error. */
void skan_log_warn(const char *format, ...);

/** Log an ERROR message to standard error. */
void skan_log_error(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* SKAN_CORE_LOG_H */
