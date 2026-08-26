#ifndef SKAN_NET_INTERFACE_HPP
#define SKAN_NET_INTERFACE_HPP

#include <string_view>
#include <optional>
#include <vector>

#include "net/interface_types.hpp"

namespace skan::net {

struct TransportPreflightResult final {
    PreflightCategory category{PreflightCategory::Ready};
    core::AddressFamily family{core::AddressFamily::Unknown};
    int system_error{0};
    std::string message;

    bool success() const noexcept { return category == PreflightCategory::Ready; }
};

/** Validate an explicit interface and family before a raw Linux operation. */
TransportPreflightResult preflight_interface(
    std::string_view name,
    core::AddressFamily family,
    bool require_route,
    bool require_injection) noexcept;

/** Enumerate usable Linux interfaces in deterministic name order. */
InterfaceEnumerationResult enumerate_interfaces_result();

/** Convenience API returning an empty vector when enumeration fails. */
std::vector<NetworkInterface> enumerate_interfaces();

/** Select one deterministic interface that has source/route evidence for every target family. */
InterfaceResult select_interface_for_target(const core::Target &target);

/** Look up one interface by its exact kernel name. */
InterfaceResult find_interface_result(std::string_view name);

/** Convenience API returning no value when the interface is unavailable. */
std::optional<NetworkInterface> find_interface(std::string_view name);

} // namespace skan::net

#endif // SKAN_NET_INTERFACE_HPP
