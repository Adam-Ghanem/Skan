#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "core/constants.h"
#include "core/errors.h"
#include "core/types.h"

static void test_status_strings(void)
{
    assert(strcmp(skan_status_string(SKAN_OK), "ok") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_INVALID_ARG), "invalid argument") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_MEMORY), "memory error") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_IO), "I/O error") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_PERMISSION), "permission denied") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_PARSE), "parse error") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_NOT_FOUND), "not found") == 0);
    assert(strcmp(skan_status_string(SKAN_ERR_INTERNAL), "internal error") == 0);
    assert(strcmp(skan_status_string((skan_status_t)999), "unknown status") == 0);
}

static void test_phase0_constants(void)
{
    assert(strcmp(SKAN_VERSION, "0.1.0") == 0);
    assert(SKAN_MAX_HOSTNAME_LENGTH > 1U);
    assert(SKAN_MAX_SERVICE_NAME_LENGTH > 1U);
    assert(SKAN_PROTOCOL_NUMBER_TCP == 6U);
    assert(SKAN_PROTOCOL_NUMBER_UDP == 17U);
}

static void test_core_type_initialization(void)
{
    skan_target_t target = {
        .host = { .value = "example.test" },
        .first_port = 80U,
        .last_port = 443U
    };
    skan_scan_result_t result = {
        .target = target,
        .port = 443U,
        .state = SKAN_PORT_STATE_OPEN,
        .protocol = SKAN_PROTOCOL_TCP,
        .service_name = "https",
        .has_service_name = true
    };

    assert(target.host.value[0] != '\0');
    assert(target.first_port <= target.last_port);
    assert(result.target.host.value[0] != '\0');
    assert(result.port == 443U);
    assert(result.state == SKAN_PORT_STATE_OPEN);
    assert(result.protocol == SKAN_PROTOCOL_TCP);
    assert(result.has_service_name);
    assert(strcmp(result.service_name, "https") == 0);
    assert(sizeof(target.host.value) == SKAN_MAX_HOSTNAME_LENGTH);
    assert(sizeof(result.service_name) == SKAN_MAX_SERVICE_NAME_LENGTH);
    assert(offsetof(skan_scan_result_t, target) == 0U);
}

int main(void)
{
    test_status_strings();
    test_phase0_constants();
    test_core_type_initialization();
    return 0;
}
