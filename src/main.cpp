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
#include "net/network_scan_transport.hpp"
#include "portscan/portscan.hpp"
#include "scanengine/timing_profile.hpp"

namespace {

void print_help()
{
    std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n'
              << "Nmap-inspired modular network scanning platform\n\n"
              << "Usage:\n"
              << "  skan [options]\n"
              << "  skan discover <ipv4-address> [options]\n"
              << "  skan scan <ipv4-address> [options]\n"
              << "  skan os-detect <ipv4-address> [options]\n"
              << "  skan interfaces [options]\n\n"
              << "Options:\n"
              << "  --help                 Show help\n"
              << "  --version              Show version\n"
              << "  --icmp                 Select ICMP Echo discovery\n"
              << "  --tcp                  Select TCP discovery\n"
              << "  --arp                  Select ARP discovery\n"
              << "  --tcp-port <port>      Set the explicit TCP discovery port\n"
              << "  --timeout-ms <ms>      Set the asynchronous probe timeout\n"
              << "  --tcp-ports <spec>     TCP ports: single, list, or range\n"
              << "  --method <connect|syn> TCP Connect or capability-gated SYN\n"
              << "  --transport <mode>     offline or explicit Linux raw-packet transport\n"
              << "  --max-outstanding <n>  Bound concurrent port probes\n"
              << "  --timing <T0..T5>      Select adaptive Skan timing profile\n"
              << "  --min-parallelism <n>  Set adaptive minimum parallelism\n"
              << "  --max-parallelism <n>  Set adaptive maximum parallelism\n"
              << "  --retries <n>          Set bounded adaptive timeout retries\n"
              << "  --service-detect       Detect services on OPEN TCP ports\n"
              << "  --service-db <path>    Use a project-owned service probe database\n"
              << "  --max-response-bytes <n> Bound service response bytes\n"
              << "  --max-probes <n>       Bound probes per OPEN port\n"
              << "  --output <format>      normal, json, xml, or grepable\n"
              << "  -o, --output-file <path> Write serialized output to a file (replace)\n"
              << "  --os-db <path>         Use a project-owned OS fingerprint database\n"
              << "  --json                 Emit structured output for os-detect or interfaces\n"
              << "  --interface <name>     Select an explicit interface for raw scans or inspection\n\n"
              << "Status:\n"
              << "  Phase 0 — Foundation\n"
              << "  Phase 1 — Async I/O Engine\n"
              << "  Phase 2 — Packet Layer\n"
              << "  Phase 3 — Host Discovery\n"
              << "  Phase 4 — TCP Port Scan (scoped)\n"
              << "  Phase 7 — Adaptive Timing + Scan Engine\n"
              << "  Phase 8 — Output & Result Serialization\n"
              << "  Phase 9 — Network Transport & Packet Capture\n"
              << "\nDiscovery CLI mode uses an offline recording transport.\n"
              << "Scan Connect mode uses normal nonblocking TCP sockets unless --transport offline is selected.\n"
              << "Scan SYN mode requires explicit --transport offline or --transport linux --interface <name>.\n"
              << "Service detection is opt-in, TCP-only, bounded, and restricted to OPEN scan results.\n"
              << "OS fingerprinting is an offline/injected architecture; live raw-packet transport is unavailable.\n"
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
    if (!interface_name.empty() && transport_mode != "linux") {
        std::cerr << "Error: --interface for discovery requires --transport linux.\n";
        return EXIT_FAILURE;
    }
    if (transport_mode == "linux" && interface_name.empty()) {
        std::cerr << "Error: --transport linux requires an explicit --interface <name>.\n";
        return EXIT_FAILURE;
    }

    skan::core::Target target{target_address, {skan::core::Host{target_address, std::nullopt, false}}};
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
    std::cout << target_address << " " << skan::discovery::host_state_name(discovery.host_state(target_address)) << '\n';
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
    if (argc < 3) {
        std::cerr << "Error: os-detect requires an explicit IPv4 target. Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    const std::string target_address = argv[2];
    std::string database_path = "data/os-fingerprints.db";
    std::chrono::milliseconds timeout{1000};
    std::size_t max_outstanding = 8U;
    bool json = false;
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
        } else if (argument == "--json") {
            json = true;
        } else {
            std::cerr << "Error: unknown or incomplete os-detect option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }

    skan::core::StatusCode database_status = skan::core::StatusCode::Ok;
    const skan::db::OSFingerprintDatabase database =
        skan::db::OSFingerprintDatabase::load_file(database_path, database_status);
    if (!skan::osdetect::live_os_fingerprinting_available()) {
        const std::string reason = database_status == skan::core::StatusCode::Ok
                                       ? "live OS fingerprinting transport is unavailable; no probes were sent"
                                       : "OS fingerprint database could not be loaded; no probes were sent";
        if (json) {
            std::cout << "{\"target\":\"" << json_escape(target_address)
                      << "\",\"state\":\"unavailable\",\"matches\":[],"
                      << "\"confidence\":0,\"error\":\"capability-unavailable\","
                      << "\"reason\":\"" << json_escape(reason) << "\"}\n";
        } else {
            std::cout << target_address << " state=UNAVAILABLE confidence=0 error=capability-unavailable\n"
                      << "  " << reason << "\n";
        }
        (void)timeout;
        (void)max_outstanding;
        return EXIT_SUCCESS;
    }
    (void)database;
    return EXIT_FAILURE;
}

int run_scan(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Error: scan requires an explicit IPv4 target. Use --help for usage.\n";
        return EXIT_FAILURE;
    }

    skan::portscan::PortScanConfig config;
    std::vector<skan::portscan::Port> ports;
    bool explicit_ports = false;
    bool service_detect = false;
    std::string service_database_path;
    skan::detect::ServiceDetectionConfig service_config;
    skan::output::OutputFormat output_format = skan::output::OutputFormat::Normal;
    std::string output_file_path;
    std::string transport_mode;
    std::string interface_name;
    bool adaptive_timing = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--tcp-ports" && index + 1 < argc) {
            const skan::portscan::PortSelection selection =
                skan::portscan::parse_tcp_ports(argv[++index]);
            if (selection.status != skan::core::StatusCode::Ok) {
                std::cerr << "Error: invalid TCP port selection.\n";
                return EXIT_FAILURE;
            }
            ports = selection.ports;
            explicit_ports = true;
        } else if (argument == "--method" && index + 1 < argc) {
            const std::string_view method(argv[++index]);
            if (method == "connect") {
                config.method = skan::portscan::ScanProbeType::TcpConnect;
            } else if (method == "syn") {
                config.method = skan::portscan::ScanProbeType::TcpSyn;
            } else {
                std::cerr << "Error: method must be connect or syn.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--timeout-ms" && index + 1 < argc) {
            unsigned int timeout = 0U;
            if (!parse_unsigned(argv[++index], timeout) || timeout == 0U) {
                std::cerr << "Error: invalid scan timeout.\n";
                return EXIT_FAILURE;
            }
            config.timeout = std::chrono::milliseconds{timeout};
        } else if (argument == "--max-outstanding" && index + 1 < argc) {
            unsigned int max_outstanding = 0U;
            if (!parse_unsigned(argv[++index], max_outstanding) || max_outstanding == 0U) {
                std::cerr << "Error: invalid max outstanding value.\n";
                return EXIT_FAILURE;
            }
            config.max_outstanding = static_cast<std::size_t>(max_outstanding);
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
            if (!parse_unsigned(argv[++index], value) ||
                (argument != "--retries" && value == 0U)) {
                std::cerr << "Error: adaptive timing values must be valid and parallelism must be positive.\n";
                return EXIT_FAILURE;
            }
            if (argument == "--min-parallelism") {
                config.timing_profile.min_parallelism = static_cast<std::size_t>(value);
            } else if (argument == "--max-parallelism") {
                config.timing_profile.max_parallelism = static_cast<std::size_t>(value);
            } else {
                config.timing_profile.max_retries = static_cast<std::size_t>(value);
            }
            adaptive_timing = true;
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
        } else if (argument == "--output" && index + 1 < argc) {
            if (skan::output::parse_output_format(argv[++index], output_format) != skan::output::OutputStatus::Ok) {
                std::cerr << "Error: output format must be normal, json, xml, or grepable.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "-o" || argument == "--output-file") && index + 1 < argc) {
            output_file_path = argv[++index];
            if (output_file_path.empty()) {
                std::cerr << "Error: output file path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--service-detect") {
            service_detect = true;
        } else if (argument == "--service-db" && index + 1 < argc) {
            service_database_path = argv[++index];
            if (service_database_path.empty()) {
                std::cerr << "Error: service database path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--max-response-bytes" && index + 1 < argc) {
            unsigned int max_response_bytes = 0U;
            if (!parse_unsigned(argv[++index], max_response_bytes) || max_response_bytes == 0U) {
                std::cerr << "Error: invalid max response byte count.\n";
                return EXIT_FAILURE;
            }
            service_config.max_response_bytes = static_cast<std::size_t>(max_response_bytes);
        } else if (argument == "--max-probes" && index + 1 < argc) {
            unsigned int max_probes = 0U;
            if (!parse_unsigned(argv[++index], max_probes) || max_probes == 0U) {
                std::cerr << "Error: invalid max probes value.\n";
                return EXIT_FAILURE;
            }
            service_config.max_probes_per_port = static_cast<std::size_t>(max_probes);
        } else {
            std::cerr << "Error: unknown or incomplete scan option. Use --help for usage.\n";
            return EXIT_FAILURE;
        }
    }
    if (!explicit_ports) {
        ports = skan::portscan::default_tcp_ports();
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
    service_config.adaptive_timing = adaptive_timing;
    service_config.timing_profile = config.timing_profile;
    if (config.method == skan::portscan::ScanProbeType::TcpSyn && transport_mode.empty()) {
        std::cerr << "Error: TCP SYN requires an explicit --transport linux --interface <name> "
                     "or --transport offline; no raw transport is selected implicitly.\n";
        return EXIT_FAILURE;
    }
    if (config.method == skan::portscan::ScanProbeType::TcpConnect && transport_mode == "linux") {
        std::cerr << "Error: the linux packet transport is only available for --method syn; "
                     "Connect mode uses normal TCP sockets.\n";
        return EXIT_FAILURE;
    }
    if (transport_mode == "linux" && interface_name.empty()) {
        std::cerr << "Error: --transport linux requires an explicit --interface <name>.\n";
        return EXIT_FAILURE;
    }

    const std::string target_address = argv[2];
    skan::core::Target target{target_address, {skan::core::Host{target_address, std::nullopt, false}}};
    skan::io::IOEngine io_engine;
    if (io_engine.initialization_status() != skan::core::StatusCode::Ok) {
        std::cerr << "Error: unable to initialize the asynchronous I/O engine.\n";
        return EXIT_FAILURE;
    }
    const auto scan_started = std::chrono::steady_clock::now();
    std::unique_ptr<skan::portscan::PortScanTransport> transport;
    std::unique_ptr<skan::portscan::TcpConnectTransport> connect_transport;
    std::unique_ptr<skan::portscan::RecordingPortScanTransport> offline_transport;
    std::unique_ptr<skan::net::LinuxNetworkScanTransport> linux_transport;
    if (transport_mode == "offline") {
        offline_transport = std::make_unique<skan::portscan::RecordingPortScanTransport>();
        transport = std::move(offline_transport);
    } else if (transport_mode == "linux") {
        linux_transport = std::make_unique<skan::net::LinuxNetworkScanTransport>(
            io_engine,
            skan::net::NetworkScanConfig{interface_name, 65535U, true, std::nullopt});
        const skan::net::NetworkScanResult network_status = linux_transport->open();
        if (!network_status.success()) {
            std::cerr << "Error: unable to open Linux scan transport: "
                      << skan::net::network_scan_status_name(network_status.status);
            if (!network_status.message.empty()) {
                std::cerr << " (" << network_status.message << ')';
            }
            std::cerr << '\n';
            return EXIT_FAILURE;
        }
        transport = std::move(linux_transport);
    } else {
        connect_transport = std::make_unique<skan::portscan::TcpConnectTransport>(io_engine);
        transport = std::move(connect_transport);
    }
    skan::portscan::PortScanScheduler scanner(
        io_engine,
        *transport,
        config);
    const skan::core::StatusCode submit_status = scanner.submit(target, ports);
    if (submit_status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: scan submission failed: "
                  << skan::core::status_to_string(submit_status) << '\n';
        return EXIT_FAILURE;
    }
    const skan::core::StatusCode run_status = scanner.run();
    if (run_status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: scan engine failed: " << skan::core::status_to_string(run_status) << '\n';
        return EXIT_FAILURE;
    }
    std::vector<skan::detect::ServiceResult> service_results;
    if (service_detect) {
        service_config.timeout = config.timeout;
        skan::core::StatusCode database_status = skan::core::StatusCode::Ok;
        skan::detect::ServiceProbeDatabase database = service_database_path.empty()
                                                           ? skan::detect::ServiceProbeDatabase::built_in()
                                                           : skan::detect::ServiceProbeDatabase::load_file(
                                                                 service_database_path, database_status);
        if (service_database_path.empty()) {
            database_status = database.status();
        }
        if (database_status != skan::core::StatusCode::Ok) {
            std::cerr << "Error: unable to load service probe database: "
                      << skan::core::status_to_string(database_status) << '\n';
            return EXIT_FAILURE;
        }
        skan::detect::ServiceTcpTransport service_transport(io_engine);
        skan::detect::ServiceDetector detector(
            io_engine,
            service_transport,
            service_config,
            std::move(database));
        const skan::core::StatusCode detection_submit = detector.submit(scanner.results());
        if (detection_submit != skan::core::StatusCode::Ok) {
            std::cerr << "Error: service detection submission failed: "
                      << skan::core::status_to_string(detection_submit) << '\n';
            return EXIT_FAILURE;
        }
        const skan::core::StatusCode detection_run = detector.run();
        if (detection_run != skan::core::StatusCode::Ok) {
            std::cerr << "Error: service detection failed: "
                      << skan::core::status_to_string(detection_run) << '\n';
            return EXIT_FAILURE;
        }
        service_results = detector.results();
    }
    skan::output::ScanReport report;
    report.target_spec = target_address;
    if (adaptive_timing) {
        report.timing_profile = config.timing_profile.id;
    }
    if (scanner.timing_controller() != nullptr) {
        report.timing_metrics = scanner.timing_controller()->metrics();
    }
    report.duration_ms = std::chrono::duration<double, std::milli>(
                             std::chrono::steady_clock::now() - scan_started)
                             .count();
    skan::output::HostResult host;
    host.address = target_address;
    host.ports = scanner.results();
    host.services = std::move(service_results);
    report.hosts.push_back(std::move(host));

    std::ofstream output_file;
    std::ostream *serialized_output = &std::cout;
    if (!output_file_path.empty()) {
        output_file.open(output_file_path, std::ios::out | std::ios::trunc);
        if (!output_file.is_open()) {
            std::cerr << "Error: unable to open output file: " << output_file_path << '\n';
            return EXIT_FAILURE;
        }
        serialized_output = &output_file;
    }
    const skan::output::OutputStatus output_status = skan::output::OutputManager::write(
        output_format, report, *serialized_output);
    if (output_status != skan::output::OutputStatus::Ok) {
        std::cerr << "Error: unable to serialize scan report: "
                  << skan::output::output_status_name(output_status) << '\n';
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

    if (argc >= 2 && std::string_view(argv[1]) == "os-detect") {
        return run_os_detect(argc, argv);
    }

    if (argc >= 2 && std::string_view(argv[1]) == "interfaces") {
        return run_interfaces(argc, argv);
    }

    std::cerr << "Error: unknown or missing argument. Use --help for usage.\n";
    return EXIT_FAILURE;
}
