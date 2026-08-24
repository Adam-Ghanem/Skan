#ifndef SKAN_CORE_TYPES_H
#define SKAN_CORE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A hostname or address owned by the containing host value. */
typedef struct {
    char value[SKAN_MAX_HOSTNAME_LENGTH];
} skan_host_t;

/** A transport port number. */
typedef uint16_t skan_port_t;

/** A scan target composed of a host and optional port range. */
typedef struct {
    skan_host_t host;
    skan_port_t first_port;
    skan_port_t last_port;
} skan_target_t;

typedef enum {
    SKAN_PORT_STATE_UNKNOWN = 0,
    SKAN_PORT_STATE_OPEN,
    SKAN_PORT_STATE_CLOSED,
    SKAN_PORT_STATE_FILTERED
} skan_port_state_t;

typedef enum {
    SKAN_PROTOCOL_UNKNOWN = 0,
    SKAN_PROTOCOL_TCP,
    SKAN_PROTOCOL_UDP
} skan_protocol_t;

/** The result of a future port probe, with no scanning behavior in Phase 0. */
typedef struct {
    skan_target_t target;
    skan_port_t port;
    skan_port_state_t state;
    skan_protocol_t protocol;
    char service_name[SKAN_MAX_SERVICE_NAME_LENGTH];
    bool has_service_name;
} skan_scan_result_t;

#ifdef __cplusplus
}
#endif

#endif /* SKAN_CORE_TYPES_H */
