#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string_view>
#include <sstream>
#include <string>
#include <vector>

#include "detect/service_scheduler.hpp"
#include "io/io_engine.hpp"
#include "orchestrator/scan_pipeline.hpp"
#include "net/packet_receiver.hpp"
#include "net/packet_filter.hpp"
#include "osdetect/os_matcher.hpp"
#include "osdetect/os_scheduler.hpp"
#include "output/output_manager.hpp"
#include "output/result_model.hpp"
#include "portscan/port_scheduler.hpp"
#include "portscan/udp_scan.hpp"
#include "packet/ethernet.hpp"
#include "packet/ipv4.hpp"
#include "packet/ipv6.hpp"
#include "packet/icmpv6.hpp"
#include "packet/packet.hpp"
#include "packet/udp.hpp"
#include "target/target_engine.hpp"

namespace {

using Clock = std::chrono::steady_clock;

std::string address_for(std::size_t index)
{
    return skan::target::format_ipv4(0xC6120001U + static_cast<std::uint32_t>(index));
}

std::string ipv6_address_for(std::size_t index)
{
    std::array<std::uint8_t, 16U> bytes{};
    bytes[0] = 0x20U;
    bytes[1] = 0x01U;
    bytes[2] = 0x0DU;
    bytes[3] = 0xB8U;
    const std::uint32_t value = static_cast<std::uint32_t>(index + 1U);
    bytes[12] = static_cast<std::uint8_t>(value >> 24U);
    bytes[13] = static_cast<std::uint8_t>(value >> 16U);
    bytes[14] = static_cast<std::uint8_t>(value >> 8U);
    bytes[15] = static_cast<std::uint8_t>(value);
    return skan::core::IpAddress::from_ipv6(bytes).to_string();
}

skan::core::Target target_for(std::size_t count)
{
    skan::core::Target target;
    target.original_specification = count == 0U ? "" : address_for(0U) + "-" + address_for(count - 1U);
    target.resolved_hosts.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        target.resolved_hosts.push_back(skan::core::Host{address_for(index), std::nullopt, true});
    }
    return target;
}

skan::core::Target ipv6_target_for(std::size_t count)
{
    skan::core::Target target;
    target.original_specification = count == 0U ? "" : ipv6_address_for(0U) + "-" + ipv6_address_for(count - 1U);
    target.resolved_hosts.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        const auto address = skan::core::parse_ip_address(ipv6_address_for(index));
        target.resolved_hosts.push_back(skan::core::Host{ipv6_address_for(index), std::nullopt, true, *address});
    }
    return target;
}

skan::core::Target mixed_target_for(std::size_t count)
{
    skan::core::Target target;
    target.original_specification = "mixed-offline";
    target.resolved_hosts.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        if ((index & 1U) == 0U) {
            target.resolved_hosts.push_back(skan::core::Host{address_for(index / 2U), std::nullopt, true});
        } else {
            const auto address = skan::core::parse_ip_address(ipv6_address_for(index / 2U));
            target.resolved_hosts.push_back(
                skan::core::Host{ipv6_address_for(index / 2U), std::nullopt, true, *address});
        }
    }
    return target;
}

std::vector<std::uint8_t> ipv6_udp_frame()
{
    skan::packet::Ethernet ethernet(
        {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U},
        {0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU}, 0x86DDU);
    skan::packet::IPv6 ipv6;
    ipv6.set_next_header(17U);
    ipv6.set_source_address(skan::core::parse_ip_address("2001:db8::1")->bytes);
    ipv6.set_destination_address(skan::core::parse_ip_address("2001:db8::2")->bytes);
    skan::packet::UDP udp;
    udp.set_source_port(40000U);
    udp.set_destination_port(53U);
    udp.set_payload({0x01U, 0x02U, 0x03U, 0x04U, 0x05U});
    skan::packet::Packet packet;
    packet.set_ethernet(ethernet);
    packet.set_ipv6(ipv6);
    packet.set_udp(udp);
    return packet.serialize();
}

std::vector<skan::portscan::PortResult> open_ports_for(std::size_t count)
{
    std::vector<skan::portscan::PortResult> ports;
    ports.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        skan::portscan::PortResult result;
        result.target = address_for(index);
        result.port = {80U, skan::portscan::Protocol::Tcp};
        result.state = skan::portscan::PortState::Open;
        result.probe = skan::portscan::ScanProbeType::TcpConnect;
        result.reason = skan::portscan::ScanReason::ImmediateSuccess;
        ports.push_back(std::move(result));
    }
    return ports;
}

skan::output::ScanReport report_for(std::size_t count)
{
    skan::output::ScanReport report;
    report.scanner_name = "Skan benchmark";
    report.scanner_version = "0.1.0";
    report.target_spec = count == 0U ? "" : address_for(0U) + "-" + address_for(count - 1U);
    report.hosts.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        skan::output::HostResult host;
        host.address = address_for(index);
        host.state = skan::discovery::HostState::Unknown;
        report.hosts.push_back(std::move(host));
    }
    return report;
}

std::size_t peak_rss_kib()
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmHWM:", 0U) != 0U) {
            continue;
        }
        std::istringstream fields(line.substr(std::string_view{"VmHWM:"}.size()));
        std::size_t value = 0U;
        if (fields >> value) {
            return value;
        }
    }
    return std::size_t{0U};
}

template <typename Function>
void measure(const std::string &stage, std::size_t count, Function function)
{
    std::vector<double> samples;
    samples.reserve(5U);
    std::size_t operations = 0U;
    for (std::size_t sample = 0U; sample < 5U; ++sample) {
        const auto started = Clock::now();
        operations = function();
        samples.push_back(std::chrono::duration<double, std::milli>(Clock::now() - started).count());
    }
    std::sort(samples.begin(), samples.end());
    const double milliseconds = samples[samples.size() / 2U];
    const double p95_milliseconds = samples[samples.size() - 1U];
    const double operations_per_second = milliseconds == 0.0
                                             ? 0.0
                                             : static_cast<double>(operations) / (milliseconds / 1000.0);
    std::cout << stage << ',' << count << ',' << std::fixed << std::setprecision(3) << milliseconds << ','
              << p95_milliseconds << ',' << operations_per_second << ',' << peak_rss_kib() << ',' << operations
              << '\n';
}

void benchmark_target_expansion(std::size_t count)
{
    const std::string specification = address_for(0U) + "-" + address_for(count - 1U);
    measure("target-expansion", count, [&specification, count]() {
        const auto result = skan::target::TargetEngine::resolve(
            specification, skan::target::TargetLimits{count, 64U});
        return result.success() ? result.target_set.size() : 0U;
    });
}

void benchmark_ipv6_target_expansion(std::size_t count)
{
    const std::string specification = ipv6_address_for(0U) + "-" + ipv6_address_for(count - 1U);
    measure("ipv6-target-expansion", count, [&specification, count]() {
        const auto result = skan::target::TargetEngine::resolve(
            specification, skan::target::TargetLimits{count, 64U});
        return result.success() ? result.target_set.size() : 0U;
    });
}

void benchmark_mixed_target_expansion(std::size_t count)
{
    std::string specification;
    specification.reserve(count * 40U);
    for (std::size_t index = 0U; index < count; ++index) {
        if (!specification.empty()) {
            specification.push_back(',');
        }
        specification += (index % 2U == 0U) ? address_for(index / 2U) : ipv6_address_for(index / 2U);
    }
    measure("mixed-target-expansion", count, [&specification, count]() {
        const auto result = skan::target::TargetEngine::resolve(
            specification, skan::target::TargetLimits{count, 64U});
        return result.success() ? result.target_set.size() : 0U;
    });
}

std::vector<std::uint8_t> ipv4_udp_frame()
{
    skan::packet::Ethernet ethernet(
        {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U},
        {0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU}, 0x0800U);
    skan::packet::IPv4 ipv4;
    ipv4.set_source_address(0xC0000201U);
    ipv4.set_destination_address(0xC0000202U);
    ipv4.set_protocol(17U);
    skan::packet::UDP udp;
    udp.set_source_port(40000U);
    udp.set_destination_port(53U);
    udp.set_payload({0x01U, 0x02U, 0x03U, 0x04U, 0x05U});
    skan::packet::Packet packet;
    packet.set_ethernet(ethernet);
    packet.set_ipv4(ipv4);
    packet.set_udp(udp);
    return packet.serialize();
}

void benchmark_ipv4_receiver(std::size_t count)
{
    const std::vector<std::uint8_t> frame = ipv4_udp_frame();
    measure("ipv4-receiver-parser", count, [&frame, count]() {
        std::size_t valid = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (skan::net::PacketReceiver::parse(frame).status == skan::net::ParseStatus::Valid) {
                ++valid;
            }
        }
        return valid;
    });
}

void benchmark_ipv6_receiver(std::size_t count)
{
    const std::vector<std::uint8_t> frame = ipv6_udp_frame();
    measure("ipv6-receiver-parser", count, [&frame, count]() {
        std::size_t valid = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (skan::net::PacketReceiver::parse(frame).status == skan::net::ParseStatus::Valid) {
                ++valid;
            }
        }
        return valid;
    });
}

void benchmark_ipv6_ndp(std::size_t count)
{
    const auto target = skan::core::parse_ip_address("2001:db8::42")->bytes;
    const std::array<std::uint8_t, 6U> mac{0x02U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU};
    const auto solicitation = skan::packet::ICMPv6::make_neighbor_solicitation(target, mac);
    const auto advertisement = skan::packet::ICMPv6::make_neighbor_advertisement(target, mac);
    measure("ipv6-ndp-parser", count, [&solicitation, &advertisement, count]() {
        std::size_t valid = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (solicitation.has_value()) {
                const auto parsed = skan::packet::ICMPv6::parse(solicitation->serialize());
                if (parsed.has_value() && parsed->neighbor_target().has_value() && parsed->neighbor_options().size() == 1U) {
                    ++valid;
                }
            }
            if (advertisement.has_value()) {
                const auto parsed = skan::packet::ICMPv6::parse(advertisement->serialize());
                if (parsed.has_value() && parsed->neighbor_target().has_value() && parsed->neighbor_options().size() == 1U) {
                    ++valid;
                }
            }
        }
        return valid;
    });
}

void benchmark_correlation(std::size_t count)
{
    measure("correlation-lookup", count, [count]() {
        skan::net::CorrelationTable table;
        const auto expires = Clock::now() + std::chrono::seconds{30};
        for (std::size_t index = 0U; index < count; ++index) {
            auto address = skan::core::parse_ip_address("2001:db8::1")->bytes;
            address[8] = static_cast<std::uint8_t>(index >> 8U);
            address[15] = static_cast<std::uint8_t>(index);
            skan::net::CorrelationKey key;
            key.target_ip = skan::core::IpAddress::from_ipv6(address);
            key.source_port = static_cast<std::uint16_t>(40000U + (index % 20000U));
            key.destination_port = 443U;
            key.sequence = static_cast<std::uint32_t>(index);
            if (table.insert(key, index + 1U, expires) != skan::net::CorrelationStatus::Inserted) {
                return std::size_t{0U};
            }
        }
        std::size_t found = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            auto address = skan::core::parse_ip_address("2001:db8::1")->bytes;
            address[8] = static_cast<std::uint8_t>(index >> 8U);
            address[15] = static_cast<std::uint8_t>(index);
            skan::net::CorrelationKey key;
            key.target_ip = skan::core::IpAddress::from_ipv6(address);
            key.source_port = static_cast<std::uint16_t>(40000U + (index % 20000U));
            key.destination_port = 443U;
            key.sequence = static_cast<std::uint32_t>(index);
            if (table.lookup(key, Clock::now()).status == skan::net::CorrelationStatus::Found) {
                ++found;
            }
        }
        return found;
    });
}

void benchmark_tcp(std::size_t count)
{
    const skan::core::Target target = target_for(count);
    const std::vector<skan::portscan::Port> ports{{80U, skan::portscan::Protocol::Tcp}};
    measure("tcp-scheduler", count, [&target, &ports, count]() {
        skan::io::IOEngine engine;
        skan::portscan::RecordingPortScanTransport transport;
        skan::portscan::PortScanConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        skan::portscan::PortScanScheduler scheduler(engine, transport, config);
        if (scheduler.submit(target, ports) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return scheduler.results().size();
    });
}

void benchmark_mixed_udp(std::size_t count)
{
    const skan::core::Target target = mixed_target_for(count);
    const std::vector<skan::portscan::Port> ports{{53U, skan::portscan::Protocol::Udp}};
    measure("mixed-udp-scheduler", count, [&target, &ports, count]() {
        skan::io::IOEngine engine;
        skan::portscan::RecordingUDPTransport transport;
        skan::portscan::PortScanConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        config.retries = 0U;
        skan::portscan::UDPScheduler scheduler(
            engine, transport, skan::portscan::UDPProbeDatabase::built_in(), config);
        if (scheduler.submit(target, ports) != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        std::size_t index = 0U;
        while (index < transport.submissions().size()) {
            const auto &submission = transport.submissions()[index++];
            skan::packet::UDP response_packet;
            response_packet.set_source_port(submission.port.number);
            response_packet.set_destination_port(submission.source_port);
            response_packet.set_payload({0x01U});
            std::vector<std::uint8_t> bytes(response_packet.serialized_size(), 0U);
            if (response_packet.serialize(bytes) != skan::core::StatusCode::Ok) {
                return std::size_t{0U};
            }
            skan::portscan::UDPResponse response;
            response.id = submission.id;
            response.source_ip = submission.destination_ip;
            response.source_port = submission.port.number;
            response.destination_port = submission.source_port;
            response.kind = skan::portscan::UDPResponseKind::Datagram;
            response.bytes = std::move(bytes);
            transport.deliver(response);
        }
        return scheduler.results().size();
    });
}

void benchmark_udp(std::size_t count)
{
    const skan::core::Target target = target_for(count);
    const std::vector<skan::portscan::Port> ports{{53U, skan::portscan::Protocol::Udp}};
    measure("udp-scheduler", count, [&target, &ports, count]() {
        skan::io::IOEngine engine;
        skan::portscan::RecordingUDPTransport transport;
        skan::portscan::PortScanConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        skan::portscan::UDPScheduler scheduler(
            engine, transport, skan::portscan::UDPProbeDatabase::built_in(), config);
        if (scheduler.submit(target, ports) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return scheduler.results().size();
    });
}

void benchmark_service(std::size_t count)
{
    const std::vector<skan::portscan::PortResult> ports = open_ports_for(count);
    measure("service-scheduler", count, [&ports, count]() {
        skan::io::IOEngine engine;
        skan::detect::RecordingServiceTransport transport;
        skan::detect::ServiceDetectionConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        config.max_probes_per_port = 1U;
        const skan::detect::ServiceProbeDatabase database = skan::detect::ServiceProbeDatabase::built_in();
        skan::detect::ServiceScheduler scheduler(engine, transport, database, config);
        if (scheduler.submit(ports) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return scheduler.results().size();
    });
}

void benchmark_ipv6_os_parser(std::size_t count)
{
    std::ifstream file("data/os-fingerprints-v6.db");
    std::ostringstream contents;
    contents << file.rdbuf();
    const std::string text = contents.str();
    measure("ipv6-os-parser", count, [&text, count]() {
        std::size_t parsed = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            skan::core::StatusCode status = skan::core::StatusCode::InternalError;
            const auto database = skan::db::OSFingerprintDatabase::parse(
                text, status, skan::core::AddressFamily::IPv6);
            if (status == skan::core::StatusCode::Ok && database.fingerprints().size() >= 4U) {
                parsed += database.fingerprints().size();
            }
        }
        return parsed;
    });
}

void benchmark_ipv6_os_matcher(std::size_t count)
{
    const auto database = skan::db::OSFingerprintDatabase::built_in();
    skan::osdetect::ObservedOSFingerprint observed;
    observed.family = skan::core::AddressFamily::IPv6;
    skan::osdetect::TCPObservation tcp;
    tcp.family = skan::core::AddressFamily::IPv6;
    tcp.probe_status = skan::osdetect::OSProbeStatus::ResponseReceived;
    tcp.ttl = skan::osdetect::ObservedValue<std::uint8_t>::observed(64U);
    tcp.window = skan::osdetect::ObservedValue<std::uint16_t>::observed(64240U);
    tcp.mss = skan::osdetect::ObservedValue<std::uint16_t>::observed(1440U);
    tcp.window_scale = skan::osdetect::ObservedValue<std::uint8_t>::observed(7U);
    tcp.sack_permitted = skan::osdetect::ObservedValue<bool>::observed(true);
    tcp.timestamps = skan::osdetect::ObservedValue<bool>::observed(true);
    tcp.options = {skan::packet::TcpOptionKind::Mss, skan::packet::TcpOptionKind::SackPermitted,
                   skan::packet::TcpOptionKind::Timestamp, skan::packet::TcpOptionKind::Nop,
                   skan::packet::TcpOptionKind::WindowScale};
    tcp.response_behavior = skan::osdetect::ResponseBehavior::SynAck;
    observed.tcp_observations.push_back(tcp);
    measure("ipv6-os-matcher", count, [&database, &observed, count]() {
        skan::osdetect::OSMatcher matcher(database);
        std::size_t matches = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            matches += matcher.match(observed, 3U).size();
        }
        return matches;
    });
}

void benchmark_ipv6_os_scheduler(std::size_t count)
{
    const skan::core::Target target = ipv6_target_for(count);
    measure("ipv6-os-scheduler", count, [&target, count]() {
        skan::io::IOEngine engine;
        skan::osdetect::RecordingOSProbeTransport transport;
        skan::osdetect::OSSchedulerConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        const auto database = skan::db::OSFingerprintDatabase::built_in();
        skan::osdetect::OSScheduler scheduler(engine, transport, database, config);
        if (scheduler.submit(target, {}) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return scheduler.result().has_value() ? scheduler.result()->probes_sent : 0U;
    });
}

void benchmark_mixed_os_scheduler(std::size_t count)
{
    const skan::core::Target target = mixed_target_for(count);
    measure("mixed-os-scheduler", count, [&target, count]() {
        skan::io::IOEngine engine;
        skan::osdetect::RecordingOSProbeTransport transport;
        skan::osdetect::OSSchedulerConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        const auto database = skan::db::OSFingerprintDatabase::built_in();
        skan::osdetect::OSScheduler scheduler(engine, transport, database, config);
        if (scheduler.submit(target, {}) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return scheduler.result().has_value() ? scheduler.result()->probes_sent : 0U;
    });
}

void benchmark_os(std::size_t count)
{
    const skan::core::Target target = target_for(count);
    const std::vector<skan::portscan::PortResult> ports = open_ports_for(count);
    measure("os-scheduler", count, [&target, &ports, count]() {
        skan::io::IOEngine engine;
        skan::osdetect::RecordingOSProbeTransport transport;
        skan::osdetect::OSSchedulerConfig config;
        config.timeout = std::chrono::milliseconds{1};
        config.max_outstanding = std::min<std::size_t>(count, 1024U);
        const skan::db::OSFingerprintDatabase database = skan::db::OSFingerprintDatabase::built_in();
        skan::osdetect::OSScheduler scheduler(engine, transport, database, config);
        if (scheduler.submit(target, ports) != skan::core::StatusCode::Ok ||
            scheduler.run() != skan::core::StatusCode::Ok ||
            !scheduler.result().has_value()) {
            return std::size_t{0U};
        }
        return scheduler.result()->probes_sent;
    });
}

void benchmark_mixed_orchestrator(std::size_t count)
{
    const skan::core::Target target = mixed_target_for(count);
    measure("mixed-orchestrator", count, [&target, count]() {
        skan::orchestrator::ScanConfig config;
        config.targets = {target};
        config.transport = skan::orchestrator::ScanTransport::Offline;
        config.discovery_enabled = false;
        config.port_scan_enabled = true;
        config.os_detection_enabled = true;
        config.ports = {80U};
        config.timeout = std::chrono::milliseconds{1};
        config.max_parallelism = std::min<std::size_t>(count, 1024U);
        config.output_format = skan::output::OutputFormat::Json;
        skan::orchestrator::ScanPipeline pipeline(config);
        std::ostringstream output;
        if (pipeline.run(output) != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return pipeline.report().has_value() ? pipeline.report()->hosts.size() : 0U;
    });
}

void benchmark_ipv6_orchestrator(std::size_t count)
{
    const skan::core::Target target = ipv6_target_for(count);
    measure("full-ipv6-orchestrator", count, [&target, count]() {
        skan::orchestrator::ScanConfig config;
        config.targets = {target};
        config.transport = skan::orchestrator::ScanTransport::Offline;
        config.discovery_enabled = false;
        config.port_scan_enabled = true;
        config.os_detection_enabled = true;
        config.ports = {80U};
        config.timeout = std::chrono::milliseconds{1};
        config.max_parallelism = std::min<std::size_t>(count, 1024U);
        config.output_format = skan::output::OutputFormat::Json;
        skan::orchestrator::ScanPipeline pipeline(config);
        std::ostringstream output;
        if (pipeline.run(output) != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return pipeline.report().has_value() ? pipeline.report()->hosts.size() : 0U;
    });
}

void benchmark_ipv4_orchestrator(std::size_t count)
{
    const skan::core::Target target = target_for(count);
    measure("full-ipv4-orchestrator", count, [&target, count]() {
        skan::orchestrator::ScanConfig config;
        config.targets = {target};
        config.transport = skan::orchestrator::ScanTransport::Offline;
        config.discovery_enabled = false;
        config.port_scan_enabled = true;
        config.ports = {80U};
        config.timeout = std::chrono::milliseconds{1};
        config.max_parallelism = std::min<std::size_t>(count, 1024U);
        config.output_format = skan::output::OutputFormat::Json;
        skan::orchestrator::ScanPipeline pipeline(config);
        std::ostringstream output;
        if (pipeline.run(output) != skan::core::StatusCode::Ok) {
            return std::size_t{0U};
        }
        return pipeline.report().has_value() ? pipeline.report()->hosts.size() : 0U;
    });
}

void benchmark_serialization(std::size_t count, skan::output::OutputFormat format, const char *name)
{
    const skan::output::ScanReport report = report_for(count);
    measure(name, count, [&report, format]() {
        std::ostringstream output;
        return skan::output::OutputManager::write(format, report, output) == skan::output::OutputStatus::Ok
                   ? report.hosts.size()
                   : 0U;
    });
}

void benchmark_hostname_resolution(std::size_t count)
{
    measure("hostname-resolution", count, [count]() {
        std::size_t resolved = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            const auto result = skan::target::TargetEngine::resolve(
                "localhost", skan::target::TargetLimits{8U, 8U});
            if (result.success()) {
                resolved += result.target_set.size();
            }
        }
        return resolved;
    });
}

void benchmark_packet_parser(std::size_t count, const char *name)
{
    const std::vector<std::uint8_t> frame = ipv4_udp_frame();
    measure(name, count, [&frame, count]() {
        std::size_t valid = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (skan::net::PacketReceiver::parse(frame).status == skan::net::ParseStatus::Valid) {
                ++valid;
            }
        }
        return valid;
    });
}

void benchmark_correlation_insert(std::size_t count)
{
    measure("correlation-insert", count, [count]() {
        skan::net::CorrelationTable table;
        const auto expires = Clock::now() + std::chrono::seconds{30};
        for (std::size_t index = 0U; index < count; ++index) {
            skan::net::CorrelationKey key;
            key.target_ipv4 = 0xC0000201U;
            key.source_port = static_cast<std::uint16_t>(40000U + (index % 20000U));
            key.destination_port = 443U;
            key.sequence = static_cast<std::uint32_t>(index);
            if (table.insert(key, index + 1U, expires) != skan::net::CorrelationStatus::Inserted) {
                return std::size_t{0U};
            }
        }
        return table.size();
    });
}

void benchmark_correlation_cleanup(std::size_t count)
{
    measure("correlation-cleanup", count, [count]() {
        skan::net::CorrelationTable table;
        const auto expires = Clock::now() + std::chrono::seconds{1};
        for (std::size_t index = 0U; index < count; ++index) {
            skan::net::CorrelationKey key;
            key.target_ipv4 = 0xC0000201U;
            key.source_port = static_cast<std::uint16_t>(40000U + (index % 20000U));
            key.destination_port = 443U;
            key.sequence = static_cast<std::uint32_t>(index);
            if (table.insert(key, index + 1U, expires) != skan::net::CorrelationStatus::Inserted) {
                return std::size_t{0U};
            }
        }
        return table.remove_expired(Clock::now() + std::chrono::seconds{2});
    });
}

void benchmark_timer_scheduling(std::size_t count)
{
    measure("timer-scheduling", count, [count]() {
        skan::io::IOEngine engine;
        std::size_t scheduled = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (engine.schedule(std::chrono::hours{1}, []() {}) != 0U) {
                ++scheduled;
            }
        }
        return scheduled;
    });
}

void benchmark_timer_cancellation(std::size_t count)
{
    measure("timer-cancellation", count, [count]() {
        skan::io::IOEngine engine;
        std::vector<skan::io::TimerId> timers;
        timers.reserve(count);
        for (std::size_t index = 0U; index < count; ++index) {
            const skan::io::TimerId timer = engine.schedule(std::chrono::hours{1}, []() {});
            if (timer != 0U) {
                timers.push_back(timer);
            }
        }
        std::size_t cancelled = 0U;
        for (const skan::io::TimerId timer : timers) {
            if (engine.cancel(timer) == skan::core::StatusCode::Ok) {
                ++cancelled;
            }
        }
        return cancelled;
    });
}

void benchmark_service_matching(std::size_t count, skan::portscan::Protocol protocol, const char *name)
{
    const auto database = skan::detect::ServiceProbeDatabase::built_in();
    const auto indices = database.ordered_probe_indices(
        {static_cast<std::uint16_t>(protocol == skan::portscan::Protocol::Udp ? 53U : 80U), protocol}, 1U);
    if (indices.empty()) {
        return;
    }
    const std::string response = protocol == skan::portscan::Protocol::Udp
                                     ? std::string{'\x12', '\x34'}
                                     : std::string{"HTTP/1.1 200 OK"};
    measure(name, count, [&database, &indices, &response, count]() {
        skan::detect::ServiceMatcher matcher(database);
        std::size_t matched = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            if (matcher.match(database.probes()[indices.front()], response).matched) {
                ++matched;
            }
        }
        return matched;
    });
}

void benchmark_ipv4_os_matching(std::size_t count)
{
    const auto database = skan::db::OSFingerprintDatabase::built_in();
    skan::osdetect::ObservedOSFingerprint observed;
    observed.family = skan::core::AddressFamily::IPv4;
    skan::osdetect::TCPObservation tcp;
    tcp.family = skan::core::AddressFamily::IPv4;
    tcp.probe_status = skan::osdetect::OSProbeStatus::ResponseReceived;
    tcp.ttl = skan::osdetect::ObservedValue<std::uint8_t>::observed(64U);
    tcp.window = skan::osdetect::ObservedValue<std::uint16_t>::observed(64240U);
    tcp.mss = skan::osdetect::ObservedValue<std::uint16_t>::observed(1460U);
    tcp.response_behavior = skan::osdetect::ResponseBehavior::SynAck;
    observed.tcp_observations.push_back(tcp);
    measure("ipv4-os-matcher", count, [&database, &observed, count]() {
        skan::osdetect::OSMatcher matcher(database);
        std::size_t matches = 0U;
        for (std::size_t index = 0U; index < count; ++index) {
            matches += matcher.match(observed, 3U).size();
        }
        return matches;
    });
}

} // namespace

int main(int argc, char **argv)
{
    std::vector<std::size_t> counts{100U, 1000U, 10000U};
    if (argc > 1) {
        counts = {static_cast<std::size_t>(std::stoull(argv[1]))};
    }
    std::cout << "stage,target_count,median_wall_ms,p95_wall_ms,operations_per_second,peak_rss_kib,operations\n";
    for (const std::size_t count : counts) {
        benchmark_target_expansion(count);
        benchmark_ipv6_target_expansion(count);
        benchmark_mixed_target_expansion(count);
        benchmark_hostname_resolution(count);
        benchmark_ipv4_receiver(count);
        benchmark_ipv6_receiver(count);
        benchmark_packet_parser(count, "tcp-parser");
        benchmark_packet_parser(count, "udp-parser");
        benchmark_packet_parser(count, "icmp-parser");
        benchmark_packet_parser(count, "icmpv6-parser");
        benchmark_ipv6_ndp(count);
        benchmark_ipv6_os_parser(count);
        benchmark_ipv6_os_matcher(count);
        benchmark_ipv6_os_scheduler(count);
        benchmark_mixed_os_scheduler(count);
        benchmark_ipv4_os_matching(count);
        benchmark_tcp(count);
        benchmark_udp(count);
        benchmark_mixed_udp(count);
        benchmark_service(count);
        benchmark_service_matching(count, skan::portscan::Protocol::Tcp, "tcp-service-matching");
        benchmark_service_matching(count, skan::portscan::Protocol::Udp, "udp-service-matching");
        benchmark_os(count);
        benchmark_correlation_insert(count);
        benchmark_correlation(count);
        benchmark_correlation_cleanup(count);
        benchmark_timer_scheduling(count);
        benchmark_timer_cancellation(count);
        benchmark_ipv4_orchestrator(count);
        benchmark_ipv6_orchestrator(count);
        benchmark_mixed_orchestrator(count);
        benchmark_serialization(count, skan::output::OutputFormat::Json, "json-serialization");
        benchmark_serialization(count, skan::output::OutputFormat::Xml, "xml-serialization");
        benchmark_serialization(count, skan::output::OutputFormat::Grepable, "grepable-serialization");
        benchmark_serialization(count, skan::output::OutputFormat::Normal, "normal-serialization");
    }
    return 0;
}
