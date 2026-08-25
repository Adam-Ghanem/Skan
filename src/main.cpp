#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/constants.hpp"
#include "core/status.hpp"
#include "db/os_db.hpp"
#include "detect/service_detector.hpp"
#include "discovery/discovery.hpp"
#include "osdetect/os_probe.hpp"
#include "output/output_manager.hpp"
#include "output/result_model.hpp"
#include "net/interface.hpp"
#include "net/linux_discovery_transport.hpp"
#include "net/linux_os_probe_transport.hpp"
#include "net/network_scan_transport.hpp"
#include "orchestrator/scan_orchestrator.hpp"
#include "portscan/portscan.hpp"
#include "portscan/udp_scan.hpp"
#include "scanengine/timing_profile.hpp"
#include "target/target_engine.hpp"

namespace {

void print_help()
{
    std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n'
              << "Nmap-inspired modular network scanning platform\n\n"
              << "Usage:\n"
              << "  skan [options]\n"
              << "  skan discover <ip-address> [options]\n"
              << "  skan scan <target-spec> [options]\n"
              << "  skan os-detect <ip-address> [options]\n"
              << "  skan interfaces [options]\n"
              << "  skan resolve <target-spec> [options]\n\n"
              << "Options:\n"
              << "  --help                 Show help\n"
              << "  --version              Show version\n"
              << "  --icmp                 Select ICMP Echo discovery\n"
              << "  --tcp                  Select TCP discovery\n"
              << "  --arp                  Select ARP discovery\n"
              << "  --tcp-port <port>      Set the explicit TCP discovery port\n"
              << "  --timeout-ms <ms>      Set the asynchronous probe timeout\n"
              << "  --tcp-ports <spec>     TCP ports: single, list, or range\n"
              << "  --udp                  Run the explicit bounded UDP scan mode\n"
              << "  --udp-ports <spec>     UDP ports: single, list, or range\n"
              << "  --method <connect|syn> TCP Connect or capability-gated SYN (not with --udp)\n"
              << "  --transport <mode>     offline or explicit Linux raw-packet transport\n"
              << "  --max-outstanding <n>  Bound concurrent TCP probes\n"
              << "  --udp-max-outstanding <n> Bound concurrent UDP probes (default 64)\n"
              << "  --udp-timeout-ms <ms>  Bound UDP response timeout (default 1500)\n"
              << "  --udp-retries <n>      Bound UDP timeout retries (default 1)\n"
              << "  --timing <T0..T5>      Select adaptive Skan timing profile\n"
              << "  --min-parallelism <n>  Set adaptive minimum parallelism\n"
              << "  --max-parallelism <n>  Set adaptive maximum parallelism\n"
              << "  --retries <n>          Set bounded adaptive timeout retries\n"
              << "  --adaptive-timing      Enable adaptive timing controls\n"
              << "  --discovery            Run host discovery before port scanning\n"
              << "  --no-discovery         Skip host discovery (default)\n"
              << "  --service-detect       Detect services on OPEN TCP ports\n"
              << "  --os-detect            Run capability-honest OS detection\n"
              << "  --service-db <path>    Use a project-owned service probe database\n"
              << "  --max-response-bytes <n> Bound service response bytes\n"
              << "  --max-probes <n>       Bound probes per OPEN port\n"
              << "  --output <format>      normal, json, xml, or grepable\n"
              << "  -o, --output-file <path> Write serialized output to a file (replace)\n"
              << "  --os-db <path>         Use a project-owned OS fingerprint database\n"
              << "  --json                 Emit structured output for resolve, os-detect, or interfaces\n"
              << "  --interface <name>     Select an explicit interface for raw scans or inspection\n"
              << "  --max-targets <n>      Bound CIDR/range/hostname expansion (default 4096)\n"
              << "  --max-hostname-results <n> Bound A records per hostname (default 64)\n\n"
              << "Status:\n"
              << "  Phase 0 — Foundation\n"
              << "  Phase 1 — Async I/O Engine\n"
              << "  Phase 2 — Packet Layer\n"
              << "  Phase 3 — Host Discovery\n"
              << "  Phase 4 — TCP Port Scan (scoped)\n"
              << "  Phase 7 — Adaptive Timing + Scan Engine\n"
              << "  Phase 8 — Output & Result Serialization\n"
              << "  Phase 9 — Network Transport & Packet Capture\n"
              << "  Phase 10 — Real Network Integration\n"
              << "  Phase 11 — Unified Scan Orchestrator\n"
              << "  Phase 12 — Target Resolution and Target Engine\n"
              << "  Phase 13 — Bounded UDP Scan Engine\n"
              << "  Phase 14 — Live OS Fingerprinting Engine\n"
              << "\nTarget specifications accept IPv4/IPv6, CIDR, inclusive ranges, hostnames, and comma-separated mixtures.\n"
              << "The resolve command normalizes targets without scanning; use --max-targets to bound expansion.\n"
              << "Discovery CLI mode uses an offline recording transport; Linux IPv6 discovery is reported unavailable without fallback.\n"
              << "Scan Connect mode uses normal nonblocking TCP sockets unless --transport offline is selected.\n"
              << "Scan SYN mode requires explicit --transport offline or --transport linux --interface <name>.\n"
              << "The scan pipeline runs Discovery, TCP Port, UDP (when --udp), Service, OS, and Output stages sequentially.\n"
              << "Service detection is opt-in, TCP-only, bounded, and restricted to OPEN scan results.\n"
              << "OS fingerprinting supports deterministic offline/injected probes and explicit Linux raw-packet mode.\n"
              << "UDP timeout is OPEN_OR_FILTERED; UDP service/OS inference is not fabricated.\n"
              << "Linux raw-packet failures are reported; Skan never silently falls back or fabricates results.\n";
}

bool parse_unsigned(std::string_view text, unsigned int &value)
{
    if (text.empty()) {
        return false;
    }
    const char *first = text.data();
    const char *last = text.data() + static_cast<std::ptrdiff_t>(text.size());
    const auto parsed = std::from_chars(first, last, value, 10);
    return parsed.ec == std::errc{} && parsed.ptr == last;
}

int run_discover(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Error: discover requires an explicit IPv4 target. Use --help for usage.\n";
        return EXIT_FAILURE;
    }

    const std::string target_address = argv[2];
    const auto parsed_target_address = skan::target::parse_ip_address(target_address);
    if (!parsed_target_address.has_value()) {
        std::cerr << "Error: discover requires one valid IPv4 or IPv6 address.\n";
        return EXIT_FAILURE;
    }
    const std::string canonical_target_address = skan::target::format_ip_address(*parsed_target_address);
    skan::discovery::DiscoveryConfig config;
    std::vector<skan::discovery::ProbeType> selected_probes;
    std::string transport_mode;
    std::string interface_name;
    bool explicit_probe_selection = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--icmp") {
            selected_probes.push_back(skan::discovery::ProbeType::IcmpEcho);
            explicit_probe_selection = true;
        } else if (argument == "--tcp") {
            selected_probes.push_back(skan::discovery::ProbeType::Tcp);
            explicit_probe_selection = true;
        } else if (argument == "--arp") {
            selected_probes.push_back(skan::discovery::ProbeType::Arp);
            explicit_probe_selection = true;
        } else if (argument == "--tcp-port" && index + 1 < argc) {
            unsigned int port = 0U;
            if (!parse_unsigned(argv[++index], port) || port == 0U || port > 65535U) {
                std::cerr << "Error: invalid TCP discovery port.\n";
                return EXIT_FAILURE;
            }
            config.tcp_port = static_cast<std::uint16_t>(port);
        } else if (argument == "--transport" && index + 1 < argc) {
            transport_mode = argv[++index];
            if (transport_mode != "offline" && transport_mode != "linux") {
                std::cerr << "Error: transport must be offline or linux.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--interface" && index + 1 < argc) {
            interface_name = argv[++index];
            if (interface_name.empty()) {
                std::cerr << "Error: interface name cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--timeout-ms" && index + 1 < argc) {
            unsigned int timeout = 0U;
            if (!parse_unsigned(argv[++index], timeout) || timeout == 0U) {
                std::cerr << "Error: invalid discovery timeout.\n";
                return EXIT_FAILURE;
            }
            config.timeout = std::chrono::milliseconds{timeout};
        } else {
            std::cerr << "Error: unknown or incomplete discover option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }
    if (explicit_probe_selection) {
        config.probes = std::move(selected_probes);
    }
    if (parsed_target_address->is_ipv6() &&
        std::find(config.probes.begin(), config.probes.end(), skan::discovery::ProbeType::Arp) != config.probes.end()) {
        std::cerr << "Error: ARP discovery is IPv4-only; use ICMP or TCP for IPv6.\n";
        return EXIT_FAILURE;
    }
    if (!interface_name.empty() && transport_mode != "linux") {
        std::cerr << "Error: --interface for discovery requires --transport linux.\n";
        return EXIT_FAILURE;
    }
    if (transport_mode == "linux" && interface_name.empty()) {
        std::cerr << "Error: --transport linux requires an explicit --interface <name>.\n";
        return EXIT_FAILURE;
    }
    if (transport_mode == "linux" && parsed_target_address->is_ipv6()) {
        std::cerr << "Error: Linux IPv6 discovery is unavailable in this phase; no fallback transport is used.\n";
        return EXIT_FAILURE;
    }

    skan::core::Target target{
        canonical_target_address,
        {skan::core::Host{canonical_target_address, std::nullopt, false, *parsed_target_address}}};
    skan::io::IOEngine io_engine;
    if (io_engine.initialization_status() != skan::core::StatusCode::Ok) {
        std::cerr << "Error: unable to initialize the asynchronous I/O engine.\n";
        return EXIT_FAILURE;
    }
    std::unique_ptr<skan::discovery::DiscoveryTransport> transport;
    std::unique_ptr<skan::discovery::RecordingTransport> offline_transport;
    std::unique_ptr<skan::net::LinuxDiscoveryTransport> linux_transport;
    skan::net::LinuxDiscoveryTransport *linux_transport_ptr = nullptr;
    if (transport_mode == "linux") {
        linux_transport = std::make_unique<skan::net::LinuxDiscoveryTransport>(io_engine, interface_name);
        const skan::net::NetworkScanResult network_status = linux_transport->open();
        if (!network_status.success()) {
            std::cerr << "Error: unable to open Linux discovery transport: "
                      << skan::net::network_scan_status_name(network_status.status);
            if (!network_status.message.empty()) {
                std::cerr << " (" << network_status.message << ')';
            }
            std::cerr << '\n';
            return EXIT_FAILURE;
        }
        linux_transport_ptr = linux_transport.get();
        transport = std::move(linux_transport);
    } else {
        offline_transport = std::make_unique<skan::discovery::RecordingTransport>();
        transport = std::move(offline_transport);
    }
    skan::discovery::Discovery discovery(
        io_engine, config, *transport);
    if (linux_transport_ptr != nullptr) {
        linux_transport_ptr->set_response_handler(
            [&discovery](const skan::discovery::DiscoveryResponse &response) {
                (void)discovery.receive(response);
            });
    }
    const skan::core::StatusCode submit_status = discovery.submit(target);
    if (submit_status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: discovery submission failed: "
                  << skan::core::status_to_string(submit_status) << '\n';
        return EXIT_FAILURE;
    }
    const skan::core::StatusCode run_status = discovery.run();
    if (run_status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: discovery engine failed: " << skan::core::status_to_string(run_status) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << canonical_target_address << " " << skan::discovery::host_state_name(discovery.host_state(canonical_target_address)) << '\n';
    for (const skan::discovery::DiscoveryResult &result : discovery.results()) {
        std::cout << "  " << skan::discovery::probe_type_name(result.probe)
                  << ": " << skan::discovery::discovery_reason_name(result.reason);
        if (result.rtt_ms.has_value()) {
            std::cout << " rtt_ms=" << *result.rtt_ms;
        }
        std::cout << '\n';
    }
    return EXIT_SUCCESS;
}

void print_target_error(const skan::target::TargetError &error)
{
    std::cerr << "Error: " << skan::target::target_error_name(error.code);
    if (!error.message.empty()) {
        std::cerr << ": " << error.message;
    }
    std::cerr << '\n';
}

int run_resolve(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Error: resolve requires a target specification. Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    skan::target::TargetLimits limits;
    bool json = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--json") {
            json = true;
        } else if ((argument == "--max-targets" || argument == "--max-hostname-results") && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: target limits must be positive integers.\n";
                return EXIT_FAILURE;
            }
            if (argument == "--max-targets") {
                limits.max_targets = static_cast<std::size_t>(value);
            } else {
                limits.max_hostname_results = static_cast<std::size_t>(value);
            }
        } else {
            std::cerr << "Error: unknown or incomplete resolve option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }

    const skan::target::TargetResolutionResult resolved = skan::target::TargetEngine::resolve(argv[2], limits);
    if (!resolved.success()) {
        print_target_error(resolved.error);
        return EXIT_FAILURE;
    }
    if (json) {
        std::cout << "{\"targets\":[";
        for (std::size_t index = 0U; index < resolved.target_set.targets.size(); ++index) {
            if (index != 0U) {
                std::cout << ',';
            }
            const skan::core::IpAddress &address = resolved.target_set.targets[index].ip_address;
            std::cout << "{\"address\":\"" << skan::target::format_ip_address(address)
                      << "\",\"family\":\"" << skan::core::address_family_name(address.family) << "\"}";
        }
        std::cout << "]}\n";
    } else {
        for (const skan::target::ResolvedTarget &target : resolved.target_set.targets) {
            std::cout << skan::target::format_ip_address(target.ip_address) << '\n';
        }
    }
    return EXIT_SUCCESS;
}

std::string json_escape(std::string_view value)
{
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        if (character == '"' || character == '\\') {
            escaped.push_back('\\');
        }
        escaped.push_back(character);
    }
    return escaped;
}

std::string interface_address_text(const skan::net::InterfaceAddress &address)
{
    return std::to_string(address.ipv4[0]) + "." + std::to_string(address.ipv4[1]) + "." +
           std::to_string(address.ipv4[2]) + "." + std::to_string(address.ipv4[3]);
}

void write_interfaces_json(const std::vector<skan::net::NetworkInterface> &interfaces)
{
    std::cout << "{\"interfaces\":[";
    for (std::size_t index = 0U; index < interfaces.size(); ++index) {
        const skan::net::NetworkInterface &interface = interfaces[index];
        if (index != 0U) {
            std::cout << ',';
        }
        std::cout << "{\"name\":\"" << json_escape(interface.name)
                  << "\",\"index\":" << interface.index
                  << ",\"up\":" << (interface.is_up ? "true" : "false")
                  << ",\"addresses\":[";
        for (std::size_t address_index = 0U; address_index < interface.ipv4_addresses.size(); ++address_index) {
            const skan::net::InterfaceAddress &address = interface.ipv4_addresses[address_index];
            if (address_index != 0U) {
                std::cout << ',';
            }
            std::cout << "{\"ipv4\":\"" << interface_address_text(address)
                      << "\",\"prefix_length\":" << static_cast<unsigned int>(address.prefix_length) << '}';
        }
        std::cout << "],\"capture\":" << (interface.supports_capture ? "true" : "false")
                  << ",\"injection\":" << (interface.supports_injection ? "true" : "false") << '}';
    }
    std::cout << "]}\n";
}

void write_interfaces_normal(const std::vector<skan::net::NetworkInterface> &interfaces)
{
    for (const skan::net::NetworkInterface &interface : interfaces) {
        std::cout << "Interface\n"
                  << "Name: " << interface.name << '\n'
                  << "Index: " << interface.index << '\n';
        if (interface.ipv4_addresses.empty()) {
            std::cout << "IPv4: none\n";
        } else {
            std::cout << "IPv4: ";
            for (std::size_t index = 0U; index < interface.ipv4_addresses.size(); ++index) {
                if (index != 0U) {
                    std::cout << ", ";
                }
                const skan::net::InterfaceAddress &address = interface.ipv4_addresses[index];
                std::cout << interface_address_text(address) << '/'
                          << static_cast<unsigned int>(address.prefix_length);
            }
            std::cout << '\n';
        }
        std::cout << "State: " << (interface.is_up ? "UP" : "DOWN") << '\n'
                  << "Capture: " << (interface.supports_capture ? "available" : "unavailable") << '\n'
                  << "Injection: " << (interface.supports_injection ? "available" : "unavailable") << "\n\n";
    }
}

int run_interfaces(int argc, char **argv)
{
    bool json = false;
    std::string selected_name;
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--json") {
            json = true;
        } else if (argument == "--interface" && index + 1 < argc) {
            selected_name = argv[++index];
            if (selected_name.empty()) {
                std::cerr << "Error: interface name cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else {
            std::cerr << "Error: unknown or incomplete interfaces option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }

    const skan::net::InterfaceEnumerationResult enumeration = skan::net::enumerate_interfaces_result();
    if (!enumeration.success()) {
        std::cerr << "Error: unable to enumerate interfaces: "
                  << skan::net::interface_status_name(enumeration.status);
        if (!enumeration.message.empty()) {
            std::cerr << " (" << enumeration.message << ')';
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }
    std::vector<skan::net::NetworkInterface> interfaces;
    if (selected_name.empty()) {
        interfaces = enumeration.interfaces;
    } else {
        const auto found = std::find_if(
            enumeration.interfaces.begin(), enumeration.interfaces.end(),
            [&selected_name](const skan::net::NetworkInterface &interface) {
                return interface.name == selected_name;
            });
        if (found == enumeration.interfaces.end()) {
            std::cerr << "Error: interface was not found: " << selected_name << '\n';
            return EXIT_FAILURE;
        }
        interfaces.push_back(*found);
    }
    if (json) {
        write_interfaces_json(interfaces);
    } else {
        write_interfaces_normal(interfaces);
    }
    return EXIT_SUCCESS;
}

int run_os_detect(int argc, char **argv)
{
    if (argc == 3 && std::string_view(argv[2]) == "--help") {
        std::cout << "Usage: skan os-detect <target-spec> [options]\n"
                  << "  --os-db <path>                 Project-owned OS fingerprint database\n"
                  << "  --timeout-ms <N>               Per-probe timeout\n"
                  << "  --max-outstanding <N>          Bounded concurrent probes\n"
                  << "  --retries <N>                  Bounded timeout retries\n"
                  << "  --adaptive-timing              Enable Phase 7 adaptive timing\n"
                  << "  --interface <name>             Explicit interface for Linux raw mode\n"
                  << "  --transport offline|linux      Select transport; no implicit fallback\n"
                  << "  --json                         Emit JSON output\n"
                  << "  --output normal|json|xml|grepable\n"
                  << "  --output-file <path>            Write output to a file\n";
        return EXIT_SUCCESS;
    }
    if (argc < 3) {
        std::cerr << "Error: os-detect requires a target specification. Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    std::string database_path = "data/os-fingerprints.db";
    std::chrono::milliseconds timeout{1000};
    std::size_t max_outstanding = 8U;
    std::size_t retries = 0U;
    bool adaptive_timing = false;
    std::string transport_mode{"offline"};
    std::optional<std::string> interface_name;
    skan::output::OutputFormat output_format = skan::output::OutputFormat::Normal;
    std::optional<std::string> output_file;
    skan::target::TargetLimits target_limits;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--os-db" && index + 1 < argc) {
            database_path = argv[++index];
        } else if (argument == "--timeout-ms" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid OS detection timeout.\n";
                return EXIT_FAILURE;
            }
            timeout = std::chrono::milliseconds{value};
        } else if (argument == "--max-outstanding" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid OS detection max outstanding value.\n";
                return EXIT_FAILURE;
            }
            max_outstanding = static_cast<std::size_t>(value);
        } else if (argument == "--retries" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value)) {
                std::cerr << "Error: invalid OS detection retries value.\n";
                return EXIT_FAILURE;
            }
            retries = static_cast<std::size_t>(value);
        } else if (argument == "--adaptive-timing") {
            adaptive_timing = true;
        } else if (argument == "--interface" && index + 1 < argc) {
            interface_name = argv[++index];
            if (interface_name->empty()) {
                std::cerr << "Error: interface name cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--transport" && index + 1 < argc) {
            transport_mode = argv[++index];
            if (transport_mode != "offline" && transport_mode != "linux") {
                std::cerr << "Error: os-detect transport must be offline or linux.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--json") {
            output_format = skan::output::OutputFormat::Json;
        } else if (argument == "--output" && index + 1 < argc) {
            if (skan::output::parse_output_format(argv[++index], output_format) != skan::output::OutputStatus::Ok) {
                std::cerr << "Error: output format must be normal, json, xml, or grepable.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "-o" || argument == "--output-file") && index + 1 < argc) {
            output_file = argv[++index];
            if (output_file->empty()) {
                std::cerr << "Error: output file path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "--max-targets" || argument == "--max-hostname-results") && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: target limits must be positive integers.\n";
                return EXIT_FAILURE;
            }
            if (argument == "--max-targets") {
                target_limits.max_targets = static_cast<std::size_t>(value);
            } else {
                target_limits.max_hostname_results = static_cast<std::size_t>(value);
            }
        } else {
            std::cerr << "Error: unknown or incomplete os-detect option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }
    if (transport_mode == "linux" && !interface_name.has_value()) {
        std::cerr << "Error: --transport linux requires an explicit --interface <name>.\n";
        return EXIT_FAILURE;
    }
    if (transport_mode == "offline" && interface_name.has_value()) {
        std::cerr << "Error: --interface requires --transport linux for os-detect.\n";
        return EXIT_FAILURE;
    }
    const skan::target::TargetResolutionResult resolved =
        skan::target::TargetEngine::resolve(argv[2], target_limits);
    if (!resolved.success()) {
        print_target_error(resolved.error);
        return EXIT_FAILURE;
    }
    skan::core::Target target;
    target.original_specification = argv[2];
    target.resolved_hosts.reserve(resolved.target_set.targets.size());
    for (const skan::target::ResolvedTarget &resolved_target : resolved.target_set.targets) {
        target.resolved_hosts.push_back(skan::core::Host{
            skan::target::format_ip_address(resolved_target.ip_address), resolved_target.source_hostname, false,
            resolved_target.ip_address});
    }
    skan::orchestrator::ScanConfig config;
    config.targets.push_back(std::move(target));
    config.transport = transport_mode == "linux" ? skan::orchestrator::ScanTransport::Linux
                                                    : skan::orchestrator::ScanTransport::Offline;
    config.interface_name = interface_name;
    config.port_scan_enabled = false;
    config.service_detection_enabled = false;
    config.os_detection_enabled = true;
    config.os_db_path = database_path;
    config.timeout = timeout;
    config.max_parallelism = max_outstanding;
    config.retries = retries;
    config.adaptive_timing = adaptive_timing;
    config.output_format = output_format;
    config.output_file = output_file;
    skan::orchestrator::ScanOrchestrator orchestrator(std::move(config));
    const skan::core::StatusCode status = orchestrator.run(std::cout);
    if (status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: OS detection failed: " << skan::core::status_to_string(status);
        if (!orchestrator.session().error_message().empty()) {
            std::cerr << " (" << orchestrator.session().error_message() << ')';
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int run_scan(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Error: scan requires an explicit IPv4 target. Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    skan::orchestrator::ScanConfig config;
    const std::string target_specification = argv[2];
    skan::target::TargetLimits target_limits;
    bool explicit_ports = false;
    bool explicit_method = false;
    bool adaptive_timing = false;
    std::string transport_mode;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--udp") {
            config.udp_enabled = true;
            config.port_scan_enabled = false;
        } else if (argument == "--udp-ports" && index + 1 < argc) {
            const skan::portscan::PortSelection selection =
                skan::portscan::parse_udp_ports(argv[++index]);
            if (selection.status != skan::core::StatusCode::Ok) {
                std::cerr << "Error: invalid UDP port selection.\n";
                return EXIT_FAILURE;
            }
            config.udp_ports.clear();
            for (const skan::portscan::Port &port : selection.ports) {
                config.udp_ports.push_back(port.number);
            }
            config.udp_enabled = true;
            config.port_scan_enabled = false;
        } else if (argument == "--tcp-ports" && index + 1 < argc) {
            const skan::portscan::PortSelection selection =
                skan::portscan::parse_tcp_ports(argv[++index]);
            if (selection.status != skan::core::StatusCode::Ok) {
                std::cerr << "Error: invalid TCP port selection.\n";
                return EXIT_FAILURE;
            }
            config.ports.clear();
            for (const skan::portscan::Port &port : selection.ports) {
                config.ports.push_back(port.number);
            }
            explicit_ports = true;
        } else if (argument == "--method" && index + 1 < argc) {
            const std::string_view method(argv[++index]);
            if (method == "connect") {
                config.port_method = skan::portscan::ScanProbeType::TcpConnect;
            } else if (method == "syn") {
                config.port_method = skan::portscan::ScanProbeType::TcpSyn;
            } else {
                std::cerr << "Error: method must be connect or syn.\n";
                return EXIT_FAILURE;
            }
            explicit_method = true;
        } else if (argument == "--timeout-ms" && index + 1 < argc) {
            unsigned int timeout = 0U;
            if (!parse_unsigned(argv[++index], timeout) || timeout == 0U) {
                std::cerr << "Error: invalid scan timeout.\n";
                return EXIT_FAILURE;
            }
            config.timeout = std::chrono::milliseconds{timeout};
        } else if (argument == "--udp-timeout-ms" && index + 1 < argc) {
            unsigned int timeout = 0U;
            if (!parse_unsigned(argv[++index], timeout) || timeout == 0U) {
                std::cerr << "Error: invalid UDP timeout.\n";
                return EXIT_FAILURE;
            }
            config.udp_timeout = std::chrono::milliseconds{timeout};
        } else if (argument == "--max-outstanding" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid max outstanding value.\n";
                return EXIT_FAILURE;
            }
            config.max_parallelism = static_cast<std::size_t>(value);
        } else if (argument == "--udp-max-outstanding" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid UDP max outstanding value.\n";
                return EXIT_FAILURE;
            }
            config.udp_max_outstanding = static_cast<std::size_t>(value);
        } else if (argument == "--udp-retries" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value)) {
                std::cerr << "Error: invalid UDP retries value.\n";
                return EXIT_FAILURE;
            }
            config.udp_retries = static_cast<std::size_t>(value);
        } else if (argument == "--timing" && index + 1 < argc) {
            if (skan::scanengine::TimingProfile::parse(argv[++index], config.timing_profile) !=
                skan::core::StatusCode::Ok) {
                std::cerr << "Error: timing profile must be T0, T1, T2, T3, T4, or T5.\n";
                return EXIT_FAILURE;
            }
            adaptive_timing = true;
        } else if ((argument == "--min-parallelism" || argument == "--max-parallelism" || argument == "--retries") &&
                   index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || (argument != "--retries" && value == 0U)) {
                std::cerr << "Error: adaptive timing values must be valid and parallelism must be positive.\n";
                return EXIT_FAILURE;
            }
            if (argument == "--min-parallelism") {
                config.min_parallelism = static_cast<std::size_t>(value);
                config.timing_profile.min_parallelism = static_cast<std::size_t>(value);
            } else if (argument == "--max-parallelism") {
                config.max_parallelism = static_cast<std::size_t>(value);
                config.timing_profile.max_parallelism = static_cast<std::size_t>(value);
            } else {
                config.retries = static_cast<std::size_t>(value);
                config.timing_profile.max_retries = static_cast<std::size_t>(value);
            }
            adaptive_timing = true;
        } else if (argument == "--adaptive-timing") {
            adaptive_timing = true;
        } else if (argument == "--transport" && index + 1 < argc) {
            transport_mode = argv[++index];
            if (transport_mode != "offline" && transport_mode != "linux") {
                std::cerr << "Error: transport must be offline or linux.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "--max-targets" || argument == "--max-hostname-results") && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: target limits must be positive integers.\n";
                return EXIT_FAILURE;
            }
            if (argument == "--max-targets") {
                target_limits.max_targets = static_cast<std::size_t>(value);
            } else {
                target_limits.max_hostname_results = static_cast<std::size_t>(value);
            }
        } else if (argument == "--interface" && index + 1 < argc) {
            config.interface_name = argv[++index];
            if (config.interface_name->empty()) {
                std::cerr << "Error: interface name cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--discovery") {
            config.discovery_enabled = true;
        } else if (argument == "--no-discovery") {
            config.discovery_enabled = false;
        } else if (argument == "--service-detect") {
            config.service_detection_enabled = true;
        } else if (argument == "--os-detect") {
            config.os_detection_enabled = true;
        } else if (argument == "--output" && index + 1 < argc) {
            if (skan::output::parse_output_format(argv[++index], config.output_format) !=
                skan::output::OutputStatus::Ok) {
                std::cerr << "Error: output format must be normal, json, xml, or grepable.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "-o" || argument == "--output-file") && index + 1 < argc) {
            config.output_file = argv[++index];
            if (config.output_file->empty()) {
                std::cerr << "Error: output file path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--service-db" && index + 1 < argc) {
            config.service_db_path = argv[++index];
            if (config.service_db_path.empty()) {
                std::cerr << "Error: service database path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--max-response-bytes" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid max response byte count.\n";
                return EXIT_FAILURE;
            }
            config.max_response_bytes = static_cast<std::size_t>(value);
        } else if (argument == "--max-probes" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U) {
                std::cerr << "Error: invalid max probes value.\n";
                return EXIT_FAILURE;
            }
            config.max_probes_per_port = static_cast<std::size_t>(value);
        } else {
            std::cerr << "Error: unknown or incomplete scan option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }
    if (!explicit_ports) {
        config.ports.clear();
    }
    if (adaptive_timing) {
        config.timing_profile.maximum_timeout = config.timeout;
        if (config.timing_profile.minimum_timeout > config.timeout) {
            config.timing_profile.minimum_timeout = config.timeout;
        }
        config.timing_profile.initial_parallelism =
            std::min(std::max(config.timing_profile.initial_parallelism, config.timing_profile.min_parallelism),
                     config.timing_profile.max_parallelism);
    }
    config.adaptive_timing = adaptive_timing;
    if (transport_mode == "offline") {
        config.transport = skan::orchestrator::ScanTransport::Offline;
    } else if (transport_mode == "linux") {
        config.transport = skan::orchestrator::ScanTransport::Linux;
    } else {
        config.transport = skan::orchestrator::ScanTransport::Connect;
    }
    if (config.udp_enabled && explicit_method) {
        std::cerr << "Error: --udp cannot be combined with --method connect or --method syn; use --udp-ports instead.\n";
        return EXIT_FAILURE;
    }
    if (config.udp_enabled && transport_mode.empty()) {
        std::cerr << "Error: --udp requires an explicit --transport offline or --transport linux --interface <name>.\n";
        return EXIT_FAILURE;
    }
    if (config.port_method == skan::portscan::ScanProbeType::TcpSyn && transport_mode.empty()) {
        std::cerr << "Error: TCP SYN requires an explicit --transport linux --interface <name> or --transport offline; "
                     "no raw transport is selected implicitly.\n";
        return EXIT_FAILURE;
    }
    if (config.transport == skan::orchestrator::ScanTransport::Linux && !config.udp_enabled &&
        config.port_method != skan::portscan::ScanProbeType::TcpSyn) {
        std::cerr << "Error: the linux packet transport is only available for TCP --method syn; Connect mode uses normal TCP sockets.\n";
        return EXIT_FAILURE;
    }
    if (config.transport == skan::orchestrator::ScanTransport::Linux && !config.interface_name.has_value()) {
        std::cerr << "Error: --transport linux requires an explicit --interface <name>.\n";
        return EXIT_FAILURE;
    }
    if (config.discovery_enabled && transport_mode.empty()) {
        std::cerr << "Error: --discovery requires --transport offline or --transport linux --interface <name>.\n";
        return EXIT_FAILURE;
    }
    const skan::target::TargetResolutionResult resolved =
        skan::target::TargetEngine::resolve(target_specification, target_limits);
    if (!resolved.success()) {
        print_target_error(resolved.error);
        return EXIT_FAILURE;
    }
    skan::core::Target normalized_target;
    normalized_target.original_specification = target_specification;
    normalized_target.resolved_hosts.reserve(resolved.target_set.targets.size());
    for (const skan::target::ResolvedTarget &target : resolved.target_set.targets) {
        const skan::core::IpAddress ip_address = target.ip_address.valid()
                                                    ? target.ip_address
                                                    : skan::core::IpAddress::from_ipv4(target.address);
        normalized_target.resolved_hosts.push_back(
            skan::core::Host{skan::target::format_ip_address(ip_address), target.source_hostname, false, ip_address});
    }
    config.targets.push_back(std::move(normalized_target));
    skan::orchestrator::ScanOrchestrator orchestrator(config);
    const skan::core::StatusCode status = orchestrator.run(std::cout);
    if (status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: scan orchestration failed: " << skan::core::status_to_string(status);
        if (!orchestrator.session().error_message().empty()) {
            std::cerr << " (" << orchestrator.session().error_message() << ')';
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n';
        return EXIT_SUCCESS;
    }

    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        print_help();
        return EXIT_SUCCESS;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "discover") {
        return run_discover(argc, argv);
    }

    if (argc >= 2 && std::string_view(argv[1]) == "scan") {
        return run_scan(argc, argv);
    }

    if (argc >= 2 && std::string_view(argv[1]) == "resolve") {
        return run_resolve(argc, argv);
    }

    if (argc >= 2 && std::string_view(argv[1]) == "os-detect") {
        return run_os_detect(argc, argv);
    }

    if (argc >= 2 && std::string_view(argv[1]) == "interfaces") {
        return run_interfaces(argc, argv);
    }

    std::cerr << "Error: unknown or missing argument. Use --help for usage.\n";
    return EXIT_FAILURE;
}
