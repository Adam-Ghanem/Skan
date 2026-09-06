#include <cassert>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

#include "core/constants.hpp"

int main()
{
    using namespace skan::core::constants;

    std::ifstream version_file("VERSION");
    std::string expected_version;
    assert(std::getline(version_file, expected_version));
    std::istringstream components(expected_version);
    std::uint32_t major = 0U;
    std::uint32_t minor = 0U;
    std::uint32_t patch = 0U;
    char first_separator = 0;
    char second_separator = 0;
    assert(components >> major >> first_separator >> minor >> second_separator >> patch);
    assert(first_separator == '.' && second_separator == '.');
    assert(SKAN_VERSION_MAJOR == major);
    assert(SKAN_VERSION_MINOR == minor);
    assert(SKAN_VERSION_PATCH == patch);
    static_assert(SKAN_MIN_PORT < SKAN_MAX_PORT);
    static_assert(SKAN_PROTOCOL_NUMBER_TCP == 6U);
    static_assert(SKAN_PROTOCOL_NUMBER_UDP == 17U);

    assert(SKAN_PRODUCT_NAME == std::string_view{"Skan"});
    assert(SKAN_VERSION_STRING == expected_version);
    assert(SKAN_DISPLAY_VERSION == "Skan " + expected_version);
    assert(SKAN_MIN_PORT == static_cast<std::uint16_t>(1U));
    assert(SKAN_MAX_PORT == static_cast<std::uint16_t>(65535U));

    return 0;
}
