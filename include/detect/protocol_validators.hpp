#ifndef SKAN_DETECT_PROTOCOL_VALIDATORS_HPP
#define SKAN_DETECT_PROTOCOL_VALIDATORS_HPP
#include "detect/protocol_parsers.hpp"
#include "detect/service_db.hpp"
#include <optional>
#include <string_view>
namespace skan::detect
{
// Validators activate by resolved family, never by port or an untrusted probe name.
bool has_exchange_validator(std::string_view family) noexcept;
std::optional<ProtocolIdentity> validate_exchange(std::string_view family,
                                                  const ServiceProbeDefinition &probe,
                                                  std::string_view response, bool terminal);
} // namespace skan::detect
#endif
