#ifndef SKAN_CORE_CONSTANTS_HPP
#define SKAN_CORE_CONSTANTS_HPP

#include <cstdint>
#include <string_view>

namespace skan::core::constants {

inline constexpr std::uint32_t SKAN_VERSION_MAJOR = 0U;
inline constexpr std::uint32_t SKAN_VERSION_MINOR = 1U;
inline constexpr std::uint32_t SKAN_VERSION_PATCH = 0U;
inline constexpr std::string_view SKAN_VERSION_STRING = "Skan 0.1.0";

inline constexpr std::uint16_t SKAN_MIN_PORT = 1U;
inline constexpr std::uint16_t SKAN_MAX_PORT = 65535U;
inline constexpr std::uint8_t SKAN_PROTOCOL_NUMBER_TCP = 6U;
inline constexpr std::uint8_t SKAN_PROTOCOL_NUMBER_UDP = 17U;

} // namespace skan::core::constants

#endif // SKAN_CORE_CONSTANTS_HPP
