#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "db/os_db.hpp"
#include "detect/service_db.hpp"
#include "net/packet_receiver.hpp"
#include "packet/ethernet.hpp"
#include "packet/icmp.hpp"
#include "packet/ipv4.hpp"
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
    (void)skan::packet::TCP::parse(bytes);
    (void)skan::packet::UDP::parse(bytes);
    (void)skan::packet::ICMP::parse(bytes);
    skan::core::StatusCode status = skan::core::StatusCode::Ok;
    (void)skan::detect::ServiceProbeDatabase::parse(text, status);
    (void)skan::db::OSFingerprintDatabase::parse(text, status);
    (void)skan::portscan::parse_tcp_ports(text);
    (void)skan::portscan::parse_udp_ports(text);
    (void)skan::portscan::UDPProbeDatabase::parse(text, status);
    skan::scanengine::TimingProfile profile;
    (void)skan::scanengine::TimingProfile::parse(text, profile);
    (void)skan::target::TargetParser::parse(text);
    return 0;
}
