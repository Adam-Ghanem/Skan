#include <algorithm>
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
#include "osdetect/os_scheduler.hpp"
#include "output/output_manager.hpp"
#include "output/result_model.hpp"
#include "portscan/port_scheduler.hpp"
#include "portscan/udp_scan.hpp"
#include "target/target_engine.hpp"

namespace {

using Clock = std::chrono::steady_clock;

std::string address_for(std::size_t index)
{
    return skan::target::format_ipv4(0xC6120001U + static_cast<std::uint32_t>(index));
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

void benchmark_orchestrator(std::size_t count)
{
    const skan::core::Target target = target_for(count);
    measure("full-orchestrator", count, [&target, count]() {
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
        benchmark_tcp(count);
        benchmark_udp(count);
        benchmark_service(count);
        benchmark_os(count);
        benchmark_orchestrator(count);
        benchmark_serialization(count, skan::output::OutputFormat::Json, "json-serialization");
        benchmark_serialization(count, skan::output::OutputFormat::Xml, "xml-serialization");
    }
    return 0;
}
