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

    skan::net::NetworkInterface first;
    first.name = "zeta0";
    first.index = 9U;
    first.ipv4_addresses.push_back(address);
    first.is_up = true;
    first.supports_capture = true;
    first.supports_injection = false;
    skan::net::NetworkInterface second;
    second.name = "alpha0";
    second.index = 4U;
    std::vector<skan::net::NetworkInterface> interfaces{first, second};
    std::sort(interfaces.begin(), interfaces.end(), [](const auto &left, const auto &right) {
        return left.name < right.name;
    });
    assert(interfaces.front().name == "alpha0");
    assert(interfaces.back().index == 9U);

    const skan::net::InterfaceResult invalid = skan::net::find_interface_result("");
    assert(invalid.status == skan::net::InterfaceStatus::InvalidName);
    assert(!invalid.success());

    const skan::net::InterfaceEnumerationResult enumeration = skan::net::enumerate_interfaces_result();
    assert(enumeration.status == skan::net::InterfaceStatus::Success);
    assert(std::is_sorted(enumeration.interfaces.begin(), enumeration.interfaces.end(),
                          [](const auto &left, const auto &right) { return left.name < right.name; }));
    return 0;
}
