#include "core/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static void skan_log_vwrite(FILE *stream, const char *level, const char *format, va_list arguments)
{
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char timestamp[20] = "0000-00-00 00:00:00";

    if (local_time != NULL) {
        (void)strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
    }

    (void)fprintf(stream, "[%s] [%s] ", timestamp, level);
    if (format == NULL) {
        (void)fputs("(null)\n", stream);
    } else {
        (void)vfprintf(stream, format, arguments);
        (void)fputc('\n', stream);
    }
}

void skan_log_debug(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    skan_log_vwrite(stdout, "DEBUG", format, arguments);
    va_end(arguments);
}

void skan_log_info(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    skan_log_vwrite(stdout, "INFO", format, arguments);
    va_end(arguments);
}

void skan_log_warn(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    skan_log_vwrite(stderr, "WARN", format, arguments);
    va_end(arguments);
}

void skan_log_error(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    skan_log_vwrite(stderr, "ERROR", format, arguments);
    va_end(arguments);
}
