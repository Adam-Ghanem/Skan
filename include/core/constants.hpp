#ifndef SKAN_CORE_CONSTANTS_HPP
#define SKAN_CORE_CONSTANTS_HPP

#include <cstdint>
#include <string_view>

#ifndef SKAN_VERSION_VALUE
#error "SKAN_VERSION_VALUE must be supplied by the build system"
#endif
#ifndef SKAN_VERSION_MAJOR_VALUE
#error "SKAN_VERSION_MAJOR_VALUE must be supplied by the build system"
#endif
#ifndef SKAN_VERSION_MINOR_VALUE
#error "SKAN_VERSION_MINOR_VALUE must be supplied by the build system"
#endif
#ifndef SKAN_VERSION_PATCH_VALUE
#error "SKAN_VERSION_PATCH_VALUE must be supplied by the build system"
#endif

#define SKAN_PRODUCT_NAME_VALUE "Skan"

namespace skan::core::constants {

inline constexpr std::uint32_t SKAN_VERSION_MAJOR = SKAN_VERSION_MAJOR_VALUE;
inline constexpr std::uint32_t SKAN_VERSION_MINOR = SKAN_VERSION_MINOR_VALUE;
inline constexpr std::uint32_t SKAN_VERSION_PATCH = SKAN_VERSION_PATCH_VALUE;
inline constexpr std::string_view SKAN_PRODUCT_NAME = SKAN_PRODUCT_NAME_VALUE;
inline constexpr std::string_view SKAN_VERSION_STRING = SKAN_VERSION_VALUE;
inline constexpr std::string_view SKAN_DISPLAY_VERSION =
    SKAN_PRODUCT_NAME_VALUE " " SKAN_VERSION_VALUE;

inline constexpr std::uint16_t SKAN_MIN_PORT = 1U;
inline constexpr std::uint16_t SKAN_MAX_PORT = 65535U;
inline constexpr std::uint8_t SKAN_PROTOCOL_NUMBER_TCP = 6U;
inline constexpr std::uint8_t SKAN_PROTOCOL_NUMBER_UDP = 17U;

} // namespace skan::core::constants

#undef SKAN_PRODUCT_NAME_VALUE

#endif // SKAN_CORE_CONSTANTS_HPP
