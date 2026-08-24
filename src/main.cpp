#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
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
#include "portscan/portscan.hpp"

namespace {

void print_help()
{
    std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n'
              << "Nmap-inspired modular network scanning platform\n\n"
              << "Usage:\n"
              << "  skan [options]\n"
              << "  skan discover <ipv4-address> [options]\n"
              << "  skan scan <ipv4-address> [options]\n"
              << "  skan os-detect <ipv4-address> [options]\n\n"
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
              << "  --max-outstanding <n>  Bound concurrent port probes\n"
              << "  --service-detect       Detect services on OPEN TCP ports\n"
              << "  --service-db <path>    Use a project-owned service probe database\n"
              << "  --max-response-bytes <n> Bound service response bytes\n"
              << "  --max-probes <n>       Bound probes per OPEN port\n"
              << "  --os-db <path>         Use a project-owned OS fingerprint database\n"
              << "  --json                 Emit structured output for os-detect\n\n"
              << "Status:\n"
              << "  Phase 0 — Foundation\n"
              << "  Phase 1 — Async I/O Engine\n"
              << "  Phase 2 — Packet Layer\n"
              << "  Phase 3 — Host Discovery\n"
              << "  Phase 4 — TCP Port Scan (scoped)\n"
              << "\nDiscovery CLI mode uses an offline recording transport.\n"
              << "Scan CLI mode uses real nonblocking TCP Connect sockets.\n"
              << "Service detection is opt-in, TCP-only, bounded, and restricted to OPEN scan results.\n"
              << "OS fingerprinting is an offline/injected architecture; live raw-packet transport is unavailable.\n";
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

    skan::core::Target target{target_address, {skan::core::Host{target_address, std::nullopt, false}}};
    skan::io::IOEngine io_engine;
    if (io_engine.initialization_status() != skan::core::StatusCode::Ok) {
        std::cerr << "Error: unable to initialize the asynchronous I/O engine.\n";
        return EXIT_FAILURE;
    }
    skan::discovery::RecordingTransport transport;
    skan::discovery::Discovery discovery(
        io_engine, config, transport);
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
    if (config.method == skan::portscan::ScanProbeType::TcpSyn &&
        !skan::portscan::tcp_syn_network_capability_available()) {
        std::cerr << "Error: TCP SYN network capability is unavailable in this build; "
                     "use synthetic transport tests or --method connect.\n";
        return EXIT_FAILURE;
    }

    const std::string target_address = argv[2];
    skan::core::Target target{target_address, {skan::core::Host{target_address, std::nullopt, false}}};
    skan::io::IOEngine io_engine;
    if (io_engine.initialization_status() != skan::core::StatusCode::Ok) {
        std::cerr << "Error: unable to initialize the asynchronous I/O engine.\n";
        return EXIT_FAILURE;
    }
    skan::portscan::TcpConnectTransport transport(io_engine);
    skan::portscan::PortScanScheduler scanner(
        io_engine,
        transport,
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
    for (const skan::portscan::PortResult &result : scanner.results()) {
        std::cout << result.target << ':' << result.port.number << '/'
                  << skan::portscan::protocol_name(result.port.protocol)
                  << " state=" << skan::portscan::port_state_name(result.state)
                  << " probe=" << skan::portscan::scan_probe_type_name(result.probe)
                  << " reason=" << skan::portscan::scan_reason_name(result.reason);
        if (result.rtt_ms.has_value()) {
            std::cout << " rtt_ms=" << *result.rtt_ms;
        }
        std::cout << '\n';
    }
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
        for (const skan::detect::ServiceResult &result : detector.results()) {
            std::cout << result.target << ':' << result.port.number << '/'
                      << skan::portscan::protocol_name(result.protocol)
                      << " port_state=" << skan::portscan::port_state_name(result.port_state)
                      << " state=" << skan::detect::detection_state_name(result.state)
                      << " service=" << (result.service.empty() ? "unknown" : result.service)
                      << " product=" << (result.product.empty() ? "unknown" : result.product)
                      << " version=" << (result.version.empty() ? "unknown" : result.version)
                      << " method=" << skan::detect::detection_method_name(result.method)
                      << " probe=" << result.probe_name
                      << " confidence=" << result.confidence
                      << " error=" << skan::detect::detection_error_name(result.error);
            if (result.rtt_ms.has_value()) {
                std::cout << " rtt_ms=" << *result.rtt_ms;
            }
            std::cout << '\n';
        }
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

    std::cerr << "Error: unknown or missing argument. Use --help for usage.\n";
    return EXIT_FAILURE;
}
