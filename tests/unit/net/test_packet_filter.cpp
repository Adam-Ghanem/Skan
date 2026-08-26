#include <cassert>
#include <chrono>
#include <cstdint>

#include "net/packet_filter.hpp"

#include "net_test_fixture.hpp"

int main()
{
    const auto timestamp = std::chrono::steady_clock::time_point{std::chrono::seconds{7}};
    const skan::net::PacketObservation tcp = skan::net::PacketReceiver::parse(
        skan::test::test_tcp_frame(), timestamp);
    const skan::net::PacketObservation udp = skan::net::PacketReceiver::parse(
        skan::test::test_udp_frame(), timestamp);
    const skan::net::PacketObservation icmp = skan::net::PacketReceiver::parse(
        skan::test::test_icmp_frame(), timestamp);

    assert(skan::net::matches(skan::net::PacketFilter{}, tcp));
    assert(skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::TCP, std::nullopt, std::nullopt}, tcp));
    assert(!skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::UDP, std::nullopt, std::nullopt}, tcp));
    assert(skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::UDP, std::nullopt, std::nullopt}, udp));
    assert(skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::ICMP, std::nullopt, std::nullopt}, icmp));
    assert(skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::IPv4, std::nullopt, std::nullopt}, tcp));
    assert(skan::net::matches(skan::net::PacketFilter{std::nullopt, 12345U, 80U}, tcp));
    assert(!skan::net::matches(skan::net::PacketFilter{std::nullopt, 12345U, 443U}, tcp));
    assert(skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::UDP, 5353U, 53U}, udp));
    assert(!skan::net::matches(skan::net::PacketFilter{skan::net::PacketProtocol::TCP, 5353U, 53U}, udp));

    skan::net::PacketObservation invalid = tcp;
    invalid.status = skan::net::ParseStatus::MalformedTCP;
    assert(!skan::net::matches(skan::net::PacketFilter{}, invalid));

    skan::net::CorrelationTable table;
    const skan::net::CorrelationKey key{0x7F000001U, 12345U, 80U, 99U};
    const auto expiry = timestamp + std::chrono::seconds{10};
    assert(table.insert(key, 42U, expiry) == skan::net::CorrelationStatus::Inserted);
    assert(table.insert(key, 43U, expiry) == skan::net::CorrelationStatus::Duplicate);
    assert(table.metrics().duplicates == 1U);
    const skan::net::CorrelationResult found = table.lookup(key, timestamp + std::chrono::seconds{1});
    assert(found.status == skan::net::CorrelationStatus::Found);
    assert(found.entry->token == 42U);
    assert(table.contains(key));
    assert(table.remove(key) == skan::net::CorrelationStatus::Removed);
    assert(table.remove(key) == skan::net::CorrelationStatus::NotFound);

    const skan::net::CorrelationKey late_key{0x7F000001U, 12346U, 80U, 100U};
    assert(table.insert(late_key, 44U, expiry) == skan::net::CorrelationStatus::Inserted);
    const skan::net::CorrelationResult late = table.lookup(late_key, expiry);
    assert(late.status == skan::net::CorrelationStatus::Late);
    assert(!table.contains(late_key));
    assert(table.metrics().late == 1U);

    const skan::net::CorrelationKey expired_one{1U, 1U, 2U, 3U};
    const skan::net::CorrelationKey live_one{1U, 1U, 2U, 4U};
    assert(table.insert(expired_one, 1U, timestamp + std::chrono::seconds{1}) == skan::net::CorrelationStatus::Inserted);
    assert(table.insert(live_one, 2U, timestamp + std::chrono::seconds{20}) == skan::net::CorrelationStatus::Inserted);
    assert(table.remove_expired(timestamp + std::chrono::seconds{2}) == 1U);
    assert(table.size() == 1U);
    for (std::uint32_t index = 0U; index < 100000U; ++index) {
        const skan::net::CorrelationKey stress_key{2U, 1000U, 2000U, index};
        const auto stress_expiry = timestamp + std::chrono::seconds{30 + (index % 5U)};
        assert(table.insert(stress_key, index + 1U, stress_expiry) ==
               skan::net::CorrelationStatus::Inserted);
    }
    assert(table.size() == 100001U);
    assert(table.lookup(skan::net::CorrelationKey{2U, 1000U, 2000U, 50000U}, timestamp + std::chrono::seconds{1})
               .status == skan::net::CorrelationStatus::Found);
    assert(table.remove_expired(timestamp + std::chrono::seconds{35}) == 100001U);
    assert(table.size() == 0U);
    assert(table.metrics().cleanup_removals == 100002U);
    table.clear();
    assert(table.size() == 0U);
    return 0;
}
