#include <algorithm>
#include <array>
#include <cassert>
#include <string>

#include "net/interface.hpp"

int main()
{
    skan::net::InterfaceAddress address{{192U, 0U, 2U, 1U}, 24U};
    const std::array<std::uint8_t, 4U> expected_ipv4{192U, 0U, 2U, 1U};
    assert(address.ipv4 == expected_ipv4);
    assert(address.prefix_length == 24U);
    const auto ipv6 = skan::core::parse_ip_address("fe80::1%zeta0");
    assert(ipv6.has_value());
    skan::net::InterfaceIPv6Address ipv6_address{*ipv6, 64U};
    assert(ipv6_address.address.to_string() == "fe80::1%zeta0");

    skan::net::NetworkInterface first;
    first.name = "zeta0";
    first.index = 9U;
    first.ipv4_addresses.push_back(address);
    first.ipv6_addresses.push_back(ipv6_address);
    first.is_up = true;
    first.supports_capture = true;
    first.supports_injection = false;
    first.supports_ipv6_capture = true;
    first.supports_ipv6_injection = false;
    first.ipv6_route = {skan::net::CapabilityState::Available, first.name, skan::core::AddressFamily::IPv6,
                        "IPv6 route entry is present", 0};
    first.raw_ipv6_capture = {skan::net::CapabilityState::Unavailable, first.name, skan::core::AddressFamily::IPv6,
                              "Operation not permitted", 1};
    assert(skan::net::capability_state_name(skan::net::CapabilityState::Available) == std::string{"AVAILABLE"});
    assert(skan::net::preflight_category_name(skan::net::PreflightCategory::NoRoute) ==
           std::string{"NO_ROUTE"});
    const skan::net::TransportPreflightResult invalid_preflight = skan::net::preflight_interface(
        "", skan::core::AddressFamily::IPv4, true, true);
    assert(!invalid_preflight.success());
    assert(invalid_preflight.category == skan::net::PreflightCategory::InvalidInterface);
    const skan::net::TransportPreflightResult unsupported_preflight = skan::net::preflight_interface(
        "lo", skan::core::AddressFamily::Unknown, false, false);
    assert(!unsupported_preflight.success());
    assert(unsupported_preflight.category == skan::net::PreflightCategory::UnsupportedFamily);
    assert(first.ipv6_route.state == skan::net::CapabilityState::Available);
    assert(first.ipv6_route.family == skan::core::AddressFamily::IPv6);
    assert(first.ipv6_route.interface_name == "zeta0");
    assert(first.raw_ipv6_capture.reason == "Operation not permitted");
    assert(first.raw_ipv6_capture.diagnostic == 1);
    skan::net::NetworkInterface second;
    second.name = "alpha0";
    second.index = 4U;
    std::vector<skan::net::NetworkInterface> interfaces{first, second};
    std::sort(interfaces.begin(), interfaces.end(), [](const auto &left, const auto &right) {
        return left.name < right.name;
    });
    assert(interfaces.front().name == "alpha0");
    assert(interfaces.back().index == 9U);

    const skan::net::InterfaceResult empty_target = skan::net::select_interface_for_target(skan::core::Target{});
    assert(!empty_target.success());
    assert(empty_target.status == skan::net::InterfaceStatus::RoutingUnavailable);
    skan::core::Target invalid_target;
    invalid_target.resolved_hosts.push_back(skan::core::Host{"not-an-ip", std::nullopt, false});
    const skan::net::InterfaceResult unsupported_target = skan::net::select_interface_for_target(invalid_target);
    assert(!unsupported_target.success());
    assert(unsupported_target.status == skan::net::InterfaceStatus::NotSupported);

    const skan::net::InterfaceResult invalid = skan::net::find_interface_result("");
    assert(invalid.status == skan::net::InterfaceStatus::InvalidName);
    assert(!invalid.success());

    const skan::net::InterfaceEnumerationResult enumeration = skan::net::enumerate_interfaces_result();
    assert(enumeration.status == skan::net::InterfaceStatus::Success);
    assert(std::all_of(enumeration.interfaces.begin(), enumeration.interfaces.end(),
                       [](const auto &item) { return item.mtu >= 0U; }));
    assert(std::is_sorted(enumeration.interfaces.begin(), enumeration.interfaces.end(),
                          [](const auto &left, const auto &right) { return left.name < right.name; }));
    return 0;
}
