#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "db/os_db.hpp"
#include "detect/service_db.hpp"
#include "net/packet_receiver.hpp"
#include "osdetect/os_matcher.hpp"
#include "osdetect/os_probe.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/icmpv6.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/ipv6_extensions.hpp"
#include "packet/ipv6_quote.hpp"
#include "packet/tcp.hpp"
#include "packet/udp.hpp"
#include "portscan/port_types.hpp"
#include "portscan/udp_scan.hpp"
#include "scanengine/timing_profile.hpp"
#include "target/target_engine.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    const std::span<const std::uint8_t> bytes{data, size};
    const std::string text(reinterpret_cast<const char *>(data), size);
    (void)skan::net::PacketReceiver::parse(bytes);
    (void)skan::packet::Ethernet::parse(bytes);
    (void)skan::packet::IPv4::parse(bytes);
    (void)skan::packet::IPv6::parse(bytes);
    (void)skan::packet::parse_ipv6_extensions(bytes, size > 0U ? data[0] : 59U);
    (void)skan::packet::parse_ipv6_udp_quote(bytes);
    (void)skan::packet::TCP::parse(bytes);
    (void)skan::packet::UDP::parse(bytes);
    (void)skan::packet::ICMP::parse(bytes);
    const auto icmpv6 = skan::packet::ICMPv6::parse(bytes);
    if (icmpv6.has_value()) {
        (void)icmpv6->neighbor_target();
        (void)icmpv6->neighbor_options();
    }
    skan::core::StatusCode status = skan::core::StatusCode::Ok;
    (void)skan::detect::ServiceProbeDatabase::parse(text, status);
    (void)skan::db::OSFingerprintDatabase::parse(text, status);
    const auto ipv6_database = skan::db::OSFingerprintDatabase::parse(
        text, status, skan::core::AddressFamily::IPv6);
    skan::osdetect::ObservedOSFingerprint observed_ipv6;
    observed_ipv6.family = skan::core::AddressFamily::IPv6;
    skan::osdetect::OSMatcher matcher_ipv6(ipv6_database);
    (void)matcher_ipv6.match(observed_ipv6, 3U);
    (void)skan::portscan::parse_tcp_ports(text);
    (void)skan::portscan::parse_udp_ports(text);
    (void)skan::portscan::UDPProbeDatabase::parse(text, status);
    skan::scanengine::TimingProfile profile;
    (void)skan::scanengine::TimingProfile::parse(text, profile);
    (void)skan::target::TargetParser::parse(text);
    (void)skan::target::parse_ip_address(text);
    (void)skan::core::parse_ip_address(text);

    const skan::core::Host host{"192.0.2.10", std::nullopt, true};
    skan::osdetect::OSProbeConfig probe_config;
    for (std::uint8_t type_value = 0U; type_value <= 11U; ++type_value) {
        const auto probe = skan::osdetect::make_os_probe(
            static_cast<skan::osdetect::OSProbeType>(type_value));
        if (probe == nullptr) {
            continue;
        }
        skan::osdetect::OSProbeSubmission submission;
        if (probe->build(static_cast<skan::osdetect::OSProbeId>(size + type_value), host, probe_config, submission) !=
            skan::core::StatusCode::Ok) {
            continue;
        }
        skan::osdetect::OSProbeResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.destination_address = submission.source_address;
        response.kind = (size > 0U && (data[0] & 1U) != 0U)
                            ? skan::osdetect::OSProbeResponseKind::IcmpError
                            : skan::osdetect::OSProbeResponseKind::Data;
        response.bytes.assign(bytes.begin(), bytes.end());
        response.ip_ttl = size > 1U ? data[1] : 0U;
        (void)probe->assess(response, submission);
    }
    skan::core::Host ipv6_host;
    ipv6_host.address = "::1";
    ipv6_host.is_up = true;
    ipv6_host.ip_address = skan::core::parse_ip_address("::1").value_or(skan::core::IpAddress{});
    skan::osdetect::OSProbeConfig ipv6_config;
    ipv6_config.source_address = "::1";
    for (std::uint8_t type_value = 0U; type_value <= 11U; ++type_value) {
        const auto probe = skan::osdetect::make_os_probe(
            static_cast<skan::osdetect::OSProbeType>(type_value));
        if (probe == nullptr) {
            continue;
        }
        skan::osdetect::OSProbeSubmission submission;
        if (probe->build(static_cast<skan::osdetect::OSProbeId>(size + type_value + 100U), ipv6_host,
                         ipv6_config, submission) != skan::core::StatusCode::Ok) {
            continue;
        }
        skan::osdetect::OSProbeResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.destination_address = submission.source_address;
        response.source_ip = submission.target_ip;
        response.destination_ip = submission.source_ip;
        response.kind = skan::osdetect::OSProbeResponseKind::Data;
        response.bytes.assign(bytes.begin(), bytes.end());
        response.ip_ttl = size > 1U ? data[1] : 0U;
        (void)probe->assess(response, submission);
    }
    return 0;
}
