#include <cassert>
#include <cstdint>
#include <string_view>

#include "core/constants.hpp"

int main()
{
    using namespace skan::core::constants;

    static_assert(SKAN_VERSION_MAJOR == 0U);
    static_assert(SKAN_VERSION_MINOR == 1U);
    static_assert(SKAN_VERSION_PATCH == 0U);
    static_assert(SKAN_MIN_PORT < SKAN_MAX_PORT);
    static_assert(SKAN_PROTOCOL_NUMBER_TCP == 6U);
    static_assert(SKAN_PROTOCOL_NUMBER_UDP == 17U);

    assert(SKAN_VERSION_STRING == std::string_view{"Skan 0.1.0"});
    assert(SKAN_MIN_PORT == static_cast<std::uint16_t>(1U));
    assert(SKAN_MAX_PORT == static_cast<std::uint16_t>(65535U));

    return 0;
}
