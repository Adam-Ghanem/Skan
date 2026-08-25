#ifndef SKAN_NET_INTERFACE_HPP
#define SKAN_NET_INTERFACE_HPP

#include <string_view>
#include <optional>
#include <vector>

#include "net/interface_types.hpp"

namespace skan::net {

/** Enumerate usable Linux interfaces in deterministic name order. */
InterfaceEnumerationResult enumerate_interfaces_result();

/** Convenience API returning an empty vector when enumeration fails. */
std::vector<NetworkInterface> enumerate_interfaces();

/** Look up one interface by its exact kernel name. */
InterfaceResult find_interface_result(std::string_view name);

/** Convenience API returning no value when the interface is unavailable. */
std::optional<NetworkInterface> find_interface(std::string_view name);

} // namespace skan::net

#endif // SKAN_NET_INTERFACE_HPP
