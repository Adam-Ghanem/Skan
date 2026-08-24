#include "core/types.h"

_Static_assert(sizeof(((skan_host_t *)0)->value) == SKAN_MAX_HOSTNAME_LENGTH,
               "host storage must match the configured hostname limit");
_Static_assert(sizeof(((skan_scan_result_t *)0)->service_name) == SKAN_MAX_SERVICE_NAME_LENGTH,
               "service storage must match the configured service-name limit");
