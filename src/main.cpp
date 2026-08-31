#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <net/if.h>
#include <memory>
#include <optional>
#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unistd.h>

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

constexpr std::array<std::uint16_t, 100U> kTopTcpPorts{
    80U, 443U, 22U, 21U, 25U, 53U, 110U, 445U, 139U, 143U, 23U, 3389U, 3306U, 8080U, 1723U, 111U, 995U, 993U, 5900U, 1025U, 587U, 8888U, 199U, 1720U, 465U, 548U, 113U, 81U, 6001U, 10000U, 514U, 5060U, 179U, 1026U, 2000U, 8443U, 8000U, 32768U, 554U, 26U, 1433U, 49152U, 2001U, 515U, 8008U, 49154U, 1027U, 5666U, 646U, 5000U, 5631U, 631U, 49153U, 8081U, 2049U, 88U, 79U, 5800U, 106U, 2121U, 1110U, 49155U, 6000U, 513U, 990U, 5357U, 427U, 49156U, 543U, 544U, 5101U, 144U, 7U, 389U, 8009U, 3128U, 444U, 9999U, 5009U, 7070U, 5190U, 3000U, 5432U, 1900U, 3986U, 13U, 1029U, 9U, 5051U, 6646U, 49157U, 1028U, 873U, 1755U, 2717U, 4899U, 9100U, 119U, 37U, 1000U
};

void print_help()
{
    std::cout << skan::core::constants::SKAN_DISPLAY_VERSION << '\n'
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
              << "  -p, --tcp-ports <spec> TCP ports: single, list, range, or -p- for 1-65535\n"
              << "  --udp                  Run the explicit bounded UDP scan mode\n"
              << "  --udp-ports <spec>     UDP ports: single, list, or range\n"
              << "  --method <connect|syn> TCP Connect or capability-gated SYN (not with --udp)\n"
              << "  -sT / -sS / -sU      Nmap-style Connect, SYN, or UDP scan aliases\n"
              << "  -sn / -Pn            Discovery-only or skip-discovery aliases\n"
              << "  -sV / -O             Service/version or OS detection aliases\n"
              << "  -4 / -6              Restrict resolved targets to IPv4 or IPv6\n"
              << "  --exclude <spec>     Exclude resolved targets (repeatable)\n"
              << "  --exclude-ports <spec> Exclude ports from the active TCP/UDP selection\n"
              << "  --open               Show only OPEN or OPEN_OR_FILTERED ports\n"
              << "  --reason             Show port-state reasons in normal output\n"
              << "  --top-ports <1-100>  Scan the deterministic Skan-owned common TCP corpus\n"
              << "  -oN/-oX/-oG <file>   Normal, XML, or grepable output aliases\n"
              << "  -oA <prefix>          Write .nmap, .xml, and .gnmap outputs\n"
              << "  --transport <mode>     connect, offline, or explicit Linux raw-packet transport\n"
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
              << "  --service-detect       Detect services on supported OPEN TCP/UDP ports\n"
              << "  --os-detect            Run capability-honest OS detection\n"
              << "  --service-db <path>    Use a project-owned service probe database\n"
              << "  --max-response-bytes <n> Bound service response bytes\n"
              << "  --max-probes <n>       Bound probes per OPEN port\n"
              << "  --output <format>      normal, json, xml, or grepable\n"
              << "  --no-color             Disable ANSI colors in normal terminal output\n"
              << "  --debug                Enable diagnostic engine logging\n"
              << "  -o, --output-file <path> Write serialized output to a file (replace)\n"
              << "  --os-db <path>         Use a project-owned OS fingerprint database\n"
              << "  --json                 Emit structured output for resolve, os-detect, or interfaces\n"
              << "  --interface <name>     Select an interface for raw scans or inspection; raw scans derive one safely when omitted\n"
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
              << "Discovery CLI mode uses an offline recording transport; explicit Linux IPv6 discovery is capability-gated and reports failure without fallback.\n"
              << "Scan Connect mode uses normal nonblocking TCP sockets unless --transport offline is selected.\n"
              << "Scan SYN mode requires explicit --transport offline or --transport linux; Linux derives an interface from route/source evidence when omitted.\n"
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

bool validate_raw_ipv6_scope(const skan::core::IpAddress &address,
                             const std::optional<std::string> &interface_name,
                             std::string &error)
{
    if (!address.is_ipv6()) {
        return true;
    }
    if (address.is_ipv6_link_local() && !address.has_scope()) {
        error = "IPv6 link-local targets require an explicit %zone scope";
        return false;
    }
    if (!address.has_scope()) {
        return true;
    }
    if (!interface_name.has_value()) {
        error = "scoped IPv6 targets require an explicit --interface <name>";
        return false;
    }
    const unsigned int interface_index = ::if_nametoindex(interface_name->c_str());
    const auto scope_index = skan::core::ipv6_scope_id(address);
    if (interface_index == 0U || !scope_index.has_value()) {
        error = "IPv6 scope zone or interface could not be resolved";
        return false;
    }
    if (*scope_index != interface_index) {
        error = "IPv6 scope zone does not match --interface";
        return false;
    }
    return true;
}

int run_discover(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Error: discover requires an explicit IPv4 or IPv6 target. Use --help for usage.\n";
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
        } else if ((argument == "--interface" || argument == "-e") && index + 1 < argc) {
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
    skan::core::Target target{
        canonical_target_address,
        {skan::core::Host{canonical_target_address, std::nullopt, false, *parsed_target_address}}};
    if (transport_mode == "linux" && interface_name.empty()) {
        const skan::net::InterfaceResult selected = skan::net::select_interface_for_target(target);
        if (!selected.success()) {
            std::cerr << "Error: raw interface selection failed: " << selected.message << " ("
                      << skan::net::interface_status_name(selected.status) << ").\n";
            return EXIT_FAILURE;
        }
        interface_name = selected.interface.name;
    }
    if (transport_mode == "linux" && parsed_target_address->is_ipv6()) {
        std::string scope_error;
        if (!validate_raw_ipv6_scope(*parsed_target_address,
                                     interface_name.empty() ? std::nullopt
                                                             : std::optional<std::string>{interface_name},
                                     scope_error)) {
            std::cerr << "Error: " << scope_error << ".\n";
            return EXIT_FAILURE;
        }
    }
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
        linux_transport->set_preflight_family(parsed_target_address->is_ipv4() ? skan::core::AddressFamily::IPv4
                                                                               : skan::core::AddressFamily::IPv6);
        const skan::net::NetworkScanResult network_status = linux_transport->open();
        if (!network_status.success()) {
            std::cerr << "Error: unable to open Linux discovery transport: "
                      << skan::net::network_scan_status_name(network_status.status)
                      << " category=" << skan::net::preflight_category_name(network_status.category)
                      << " family=" << skan::core::address_family_name(network_status.family);
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

std::string interface_ipv6_address_text(const skan::net::InterfaceIPv6Address &address)
{
    return address.address.to_string();
}

void write_capability_json(const skan::net::CapabilityFact &fact)
{
    std::cout << "{\"state\":\"" << skan::net::capability_state_name(fact.state)
              << "\",\"interface\":\"" << json_escape(fact.interface_name)
              << "\",\"family\":\"" << skan::core::address_family_name(fact.family)
              << "\",\"reason\":\"" << json_escape(fact.reason) << '\"';
    if (fact.diagnostic != 0) {
        std::cout << ",\"diagnostic\":" << fact.diagnostic;
    }
    std::cout << '}';
}

void write_capability_normal(std::string_view name, const skan::net::CapabilityFact &fact)
{
    std::cout << name << ": " << skan::net::capability_state_name(fact.state)
              << " family=" << skan::core::address_family_name(fact.family)
              << " reason=" << fact.reason;
    if (fact.diagnostic != 0) {
        std::cout << " diagnostic=" << fact.diagnostic;
    }
    std::cout << '\n';
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
                  << ",\"mtu\":" << interface.mtu
                  << ",\"addresses\":[";
        for (std::size_t address_index = 0U; address_index < interface.ipv4_addresses.size(); ++address_index) {
            const skan::net::InterfaceAddress &address = interface.ipv4_addresses[address_index];
            if (address_index != 0U) {
                std::cout << ',';
            }
            std::cout << "{\"ipv4\":\"" << interface_address_text(address)
                      << "\",\"prefix_length\":" << static_cast<unsigned int>(address.prefix_length) << '}';
        }
        std::cout << "],\"ipv6_addresses\":[";
        for (std::size_t address_index = 0U; address_index < interface.ipv6_addresses.size(); ++address_index) {
            const skan::net::InterfaceIPv6Address &address = interface.ipv6_addresses[address_index];
            if (address_index != 0U) {
                std::cout << ',';
            }
            std::cout << "{\"ipv6\":\"" << json_escape(interface_ipv6_address_text(address))
                      << "\",\"prefix_length\":" << static_cast<unsigned int>(address.prefix_length) << '}';
        }
        std::cout << "],\"capture\":" << (interface.supports_capture ? "true" : "false")
                  << ",\"injection\":" << (interface.supports_injection ? "true" : "false")
                  << ",\"ipv6_capture\":" << (interface.supports_ipv6_capture ? "true" : "false")
                  << ",\"ipv6_injection\":" << (interface.supports_ipv6_injection ? "true" : "false")
                  << ",\"af_inet6\":" << (interface.supports_af_inet6 ? "true" : "false")
                  << ",\"ipv6_route\":" << (interface.supports_ipv6_route ? "true" : "false")
                  << ",\"cap_net_raw\":" << (interface.has_cap_net_raw ? "true" : "false")
                  << ",\"capabilities\":{\"ipv4\":{\"af_inet\":";
        write_capability_json(interface.af_inet);
        std::cout << ",\"route\":";
        write_capability_json(interface.ipv4_route);
        std::cout << ",\"default_route\":";
        write_capability_json(interface.ipv4_default_route);
        std::cout << ",\"source\":";
        write_capability_json(interface.ipv4_source);
        std::cout << ",\"raw_capture\":";
        write_capability_json(interface.raw_ipv4_capture);
        std::cout << ",\"raw_injection\":";
        write_capability_json(interface.raw_ipv4_injection);
        std::cout << ",\"ethernet_capture\":";
        write_capability_json(interface.ethernet_ipv4_capture);
        std::cout << ",\"ethernet_injection\":";
        write_capability_json(interface.ethernet_ipv4_injection);
        std::cout << ",\"tcp_syn\":";
        write_capability_json(interface.tcp_syn_ipv4);
        std::cout << ",\"udp\":";
        write_capability_json(interface.udp_raw_ipv4);
        std::cout << ",\"icmp\":";
        write_capability_json(interface.icmp_ipv4);
        std::cout << "},\"ipv6\":{\"af_inet6\":";
        write_capability_json(interface.af_inet6);
        std::cout << ",\"route\":";
        write_capability_json(interface.ipv6_route);
        std::cout << ",\"default_route\":";
        write_capability_json(interface.ipv6_default_route);
        std::cout << ",\"global_source\":";
        write_capability_json(interface.global_ipv6_source);
        std::cout << ",\"link_local_source\":";
        write_capability_json(interface.link_local_ipv6_source);
        std::cout << ",\"raw_capture\":";
        write_capability_json(interface.raw_ipv6_capture);
        std::cout << ",\"raw_injection\":";
        write_capability_json(interface.raw_ipv6_injection);
        std::cout << ",\"ethernet_capture\":";
        write_capability_json(interface.ethernet_ipv6_capture);
        std::cout << ",\"ethernet_injection\":";
        write_capability_json(interface.ethernet_ipv6_injection);
        std::cout << ",\"icmpv6\":";
        write_capability_json(interface.icmpv6);
        std::cout << ",\"tcp_syn\":";
        write_capability_json(interface.tcp_syn_ipv6);
        std::cout << ",\"udp\":";
        write_capability_json(interface.udp_ipv6);
        std::cout << ",\"ndp\":";
        write_capability_json(interface.ndp_ipv6);
        std::cout << "}}}";
    }
    std::cout << "]}\n";
}

void write_interfaces_normal(const std::vector<skan::net::NetworkInterface> &interfaces)
{
    for (const skan::net::NetworkInterface &interface : interfaces) {
        std::cout << "Interface\n"
                  << "Name: " << interface.name << '\n'
                  << "Index: " << interface.index << '\n'
                  << "MTU: " << interface.mtu << '\n';
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
        if (interface.ipv6_addresses.empty()) {
            std::cout << "IPv6: none\n";
        } else {
            std::cout << "IPv6: ";
            for (std::size_t index = 0U; index < interface.ipv6_addresses.size(); ++index) {
                if (index != 0U) {
                    std::cout << ", ";
                }
                const skan::net::InterfaceIPv6Address &address = interface.ipv6_addresses[index];
                std::cout << interface_ipv6_address_text(address) << '/'
                          << static_cast<unsigned int>(address.prefix_length);
            }
            std::cout << '\n';
        }
        std::cout << "State: " << (interface.is_up ? "UP" : "DOWN") << '\n'
                  << "Capture: " << (interface.supports_capture ? "available" : "unavailable") << '\n'
                  << "Injection: " << (interface.supports_injection ? "available" : "unavailable") << '\n'
                  << "IPv6 capture: " << (interface.supports_ipv6_capture ? "available" : "unavailable") << '\n'
                  << "IPv6 injection: " << (interface.supports_ipv6_injection ? "available" : "unavailable") << '\n'
                  << "AF_INET6: " << (interface.supports_af_inet6 ? "available" : "unavailable") << '\n'
                  << "IPv6 route: " << (interface.supports_ipv6_route ? "available" : "unavailable") << '\n'
                  << "CAP_NET_RAW: " << (interface.has_cap_net_raw ? "available" : "unavailable") << '\n';
        write_capability_normal("IPv4 AF_INET", interface.af_inet);
        write_capability_normal("IPv4 route", interface.ipv4_route);
        write_capability_normal("IPv4 default route", interface.ipv4_default_route);
        write_capability_normal("IPv4 source", interface.ipv4_source);
        write_capability_normal("IPv4 raw capture", interface.raw_ipv4_capture);
        write_capability_normal("IPv4 raw injection", interface.raw_ipv4_injection);
        write_capability_normal("IPv4 Ethernet capture", interface.ethernet_ipv4_capture);
        write_capability_normal("IPv4 Ethernet injection", interface.ethernet_ipv4_injection);
        write_capability_normal("IPv4 TCP SYN", interface.tcp_syn_ipv4);
        write_capability_normal("IPv4 UDP", interface.udp_raw_ipv4);
        write_capability_normal("IPv4 ICMP", interface.icmp_ipv4);
        write_capability_normal("IPv6 AF_INET6", interface.af_inet6);
        write_capability_normal("IPv6 route", interface.ipv6_route);
        write_capability_normal("IPv6 default route", interface.ipv6_default_route);
        write_capability_normal("IPv6 global source", interface.global_ipv6_source);
        write_capability_normal("IPv6 link-local source", interface.link_local_ipv6_source);
        write_capability_normal("IPv6 raw capture", interface.raw_ipv6_capture);
        write_capability_normal("IPv6 raw injection", interface.raw_ipv6_injection);
        write_capability_normal("IPv6 Ethernet capture", interface.ethernet_ipv6_capture);
        write_capability_normal("IPv6 Ethernet injection", interface.ethernet_ipv6_injection);
        write_capability_normal("IPv6 ICMPv6", interface.icmpv6);
        write_capability_normal("IPv6 TCP SYN", interface.tcp_syn_ipv6);
        write_capability_normal("IPv6 UDP", interface.udp_ipv6);
        write_capability_normal("IPv6 NDP", interface.ndp_ipv6);
        std::cout << '\n';
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
                  << "  --interface <name>             Interface for Linux raw mode; derives safely when omitted\n"
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
    std::string database_path;
    bool explicit_database_path = false;
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
            explicit_database_path = true;
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
            const unsigned int maximum = argument == "--max-targets"
                                             ? static_cast<unsigned int>(skan::target::TargetLimits::kMaximumTargets)
                                             : static_cast<unsigned int>(skan::target::TargetLimits::kMaximumHostnameResults);
            if (!parse_unsigned(argv[++index], value) || value == 0U || value > maximum) {
                std::cerr << "Error: target limit must be between 1 and " << maximum << ".\n";
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
    if (transport_mode == "linux" && !interface_name.has_value()) {
        const skan::net::InterfaceResult selected = skan::net::select_interface_for_target(target);
        if (!selected.success()) {
            std::cerr << "Error: raw interface selection failed: " << selected.message << " ("
                      << skan::net::interface_status_name(selected.status) << ").\n";
            return EXIT_FAILURE;
        }
        interface_name = selected.interface.name;
    }
    if (transport_mode == "linux") {
        for (const skan::core::Host &host : target.resolved_hosts) {
            std::string scope_error;
            if (!validate_raw_ipv6_scope(host.ip_address, interface_name, scope_error)) {
                std::cerr << "Error: " << scope_error << ".\n";
                return EXIT_FAILURE;
            }
        }
    }
    skan::orchestrator::ScanConfig config;
    config.targets.push_back(std::move(target));
    config.transport = transport_mode == "linux" ? skan::orchestrator::ScanTransport::Linux
                                                    : skan::orchestrator::ScanTransport::Offline;
    config.interface_name = interface_name;
    config.port_scan_enabled = false;
    config.service_detection_enabled = false;
    config.os_detection_enabled = true;
    config.os_db_path = explicit_database_path ? database_path : std::string{};
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
        std::cerr << "Error: scan requires an explicit IPv4 or IPv6 target. Use --help for usage.\n";
        return EXIT_FAILURE;
    }
    skan::orchestrator::ScanConfig config;
    const std::string target_specification = argv[2];
    skan::target::TargetLimits target_limits;
    bool explicit_ports = false;
    bool explicit_method = false;
    bool adaptive_timing = false;
    bool explicit_udp_ports = false;
    bool ipv4_only = false;
    bool ipv6_only = false;
    std::string transport_mode;
    std::optional<unsigned int> top_ports_count;
    std::optional<std::string> nmap_port_specification;
    std::optional<std::string> excluded_port_specification;
    std::optional<std::string> output_all_prefix;
    std::vector<std::string> excluded_target_specifications;
    bool no_color = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "-sT") {
            config.port_method = skan::portscan::ScanProbeType::TcpConnect;
            transport_mode = "connect";
            explicit_method = true;
        } else if (argument == "-sS") {
            config.port_method = skan::portscan::ScanProbeType::TcpSyn;
            transport_mode = "linux";
            explicit_method = true;
        } else if (argument == "-sU") {
            config.udp_enabled = true;
            config.port_scan_enabled = false;
            transport_mode = "linux";
        } else if (argument == "-sn") {
            config.discovery_enabled = true;
            config.port_scan_enabled = false;
            transport_mode = "linux";
        } else if (argument == "-Pn") {
            config.discovery_enabled = false;
        } else if (argument == "-sV") {
            config.service_detection_enabled = true;
        } else if (argument == "-O") {
            config.os_detection_enabled = true;
        } else if (argument == "--open") {
            config.output_context.open_only = true;
        } else if (argument == "--reason") {
            config.output_context.include_reasons = true;
        } else if (argument == "-4") {
            ipv4_only = true;
        } else if (argument == "-6") {
            ipv6_only = true;
        } else if (argument == "--exclude" && index + 1 < argc) {
            excluded_target_specifications.emplace_back(argv[++index]);
            if (excluded_target_specifications.back().empty()) {
                std::cerr << "Error: --exclude target specification cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--exclude-ports" && index + 1 < argc) {
            const std::string value(argv[++index]);
            if (value.empty()) {
                std::cerr << "Error: --exclude-ports specification cannot be empty.\n";
                return EXIT_FAILURE;
            }
            if (excluded_port_specification.has_value()) {
                *excluded_port_specification += "," + value;
            } else {
                excluded_port_specification = value;
            }
        } else if (argument.size() == 3U && argument[0] == '-' && argument[1] == 'T' &&
                   argument[2] >= '0' && argument[2] <= '5') {
            if (skan::scanengine::TimingProfile::parse(argument.substr(1U), config.timing_profile) !=
                skan::core::StatusCode::Ok) {
                std::cerr << "Error: invalid Nmap-style timing profile.\n";
                return EXIT_FAILURE;
            }
            adaptive_timing = true;
        } else if (argument == "--top-ports" && index + 1 < argc) {
            unsigned int value = 0U;
            if (!parse_unsigned(argv[++index], value) || value == 0U || value > kTopTcpPorts.size()) {
                std::cerr << "Error: --top-ports must be between 1 and " << kTopTcpPorts.size() << ".\n";
                return EXIT_FAILURE;
            }
            top_ports_count = value;
        } else if (argument == "--udp") {
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
            explicit_udp_ports = true;
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
        } else if (argument == "-p" && index + 1 < argc) {
            nmap_port_specification = argv[++index];
            if (nmap_port_specification->empty()) {
                std::cerr << "Error: -p port specification cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "-p-") {
            nmap_port_specification = "1-65535";
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
            if (transport_mode != "connect" && transport_mode != "offline" && transport_mode != "linux") {
                std::cerr << "Error: transport must be connect, offline, or linux.\n";
                return EXIT_FAILURE;
            }
        } else if ((argument == "--max-targets" || argument == "--max-hostname-results") && index + 1 < argc) {
            unsigned int value = 0U;
            const unsigned int maximum = argument == "--max-targets"
                                             ? static_cast<unsigned int>(skan::target::TargetLimits::kMaximumTargets)
                                             : static_cast<unsigned int>(skan::target::TargetLimits::kMaximumHostnameResults);
            if (!parse_unsigned(argv[++index], value) || value == 0U || value > maximum) {
                std::cerr << "Error: target limit must be between 1 and " << maximum << ".\n";
                return EXIT_FAILURE;
            }
            if (argument == "--max-targets") {
                target_limits.max_targets = static_cast<std::size_t>(value);
            } else {
                target_limits.max_hostname_results = static_cast<std::size_t>(value);
            }
        } else if ((argument == "--interface" || argument == "-e") && index + 1 < argc) {
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
        } else if ((argument == "-oN" || argument == "-oX" || argument == "-oG") && index + 1 < argc) {
            const char *format = argument == "-oN" ? "normal" : (argument == "-oX" ? "xml" : "grepable");
            if (skan::output::parse_output_format(format, config.output_format) != skan::output::OutputStatus::Ok) {
                std::cerr << "Error: invalid Nmap-style output format.\n";
                return EXIT_FAILURE;
            }
            config.output_file = argv[++index];
            if (config.output_file->empty()) {
                std::cerr << "Error: output file path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "-oA" && index + 1 < argc) {
            output_all_prefix = argv[++index];
            if (output_all_prefix->empty()) {
                std::cerr << "Error: -oA prefix cannot be empty.\n";
                return EXIT_FAILURE;
            }
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
        } else if (argument == "--no-color") {
            no_color = true;
        } else if (argument == "--debug") {
            (void)::setenv("SKAN_LOG", "debug", 1);
        } else if (argument == "--service-db" && index + 1 < argc) {
            config.service_db_path = argv[++index];
            if (config.service_db_path.empty()) {
                std::cerr << "Error: service database path cannot be empty.\n";
                return EXIT_FAILURE;
            }
        } else if (argument == "--os-db" && index + 1 < argc) {
            config.os_db_path = argv[++index];
            if (config.os_db_path.empty()) {
                std::cerr << "Error: OS database path cannot be empty.\n";
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
    if (ipv4_only && ipv6_only) {
        std::cerr << "Error: -4 and -6 cannot be combined.\n";
        return EXIT_FAILURE;
    }
    if (top_ports_count.has_value() && nmap_port_specification.has_value()) {
        std::cerr << "Error: --top-ports cannot be combined with -p or -p-.\n";
        return EXIT_FAILURE;
    }
    if (config.udp_enabled && nmap_port_specification.has_value() && explicit_udp_ports) {
        std::cerr << "Error: use either -p or --udp-ports for a UDP scan, not both.\n";
        return EXIT_FAILURE;
    }
    if (nmap_port_specification.has_value()) {
        const skan::portscan::PortSelection selection = config.udp_enabled
                                                            ? skan::portscan::parse_udp_ports(*nmap_port_specification)
                                                            : skan::portscan::parse_tcp_ports(*nmap_port_specification);
        if (selection.status != skan::core::StatusCode::Ok) {
            std::cerr << "Error: invalid " << (config.udp_enabled ? "UDP" : "TCP")
                      << " port selection for -p.\n";
            return EXIT_FAILURE;
        }
        std::vector<std::uint16_t> &selected_ports = config.udp_enabled ? config.udp_ports : config.ports;
        selected_ports.clear();
        for (const skan::portscan::Port &port : selection.ports) {
            selected_ports.push_back(port.number);
        }
        if (config.udp_enabled) {
            explicit_udp_ports = true;
        } else {
            explicit_ports = true;
        }
    }
    if (top_ports_count.has_value()) {
        if (config.udp_enabled) {
            std::cerr << "Error: the current Skan-owned --top-ports corpus is TCP-only.\n";
            return EXIT_FAILURE;
        }
        config.ports.assign(kTopTcpPorts.begin(), kTopTcpPorts.begin() + *top_ports_count);
        explicit_ports = true;
    }
    if (excluded_port_specification.has_value()) {
        const skan::portscan::PortSelection excluded = config.udp_enabled
                                                           ? skan::portscan::parse_udp_ports(*excluded_port_specification)
                                                           : skan::portscan::parse_tcp_ports(*excluded_port_specification);
        if (excluded.status != skan::core::StatusCode::Ok) {
            std::cerr << "Error: invalid --exclude-ports specification.\n";
            return EXIT_FAILURE;
        }
        std::vector<std::uint16_t> &selected_ports = config.udp_enabled ? config.udp_ports : config.ports;
        if (selected_ports.empty()) {
            const std::vector<skan::portscan::Port> defaults = config.udp_enabled
                                                                  ? skan::portscan::default_udp_ports()
                                                                  : skan::portscan::default_tcp_ports();
            for (const skan::portscan::Port &port : defaults) {
                selected_ports.push_back(port.number);
            }
            if (config.udp_enabled) {
                explicit_udp_ports = true;
            } else {
                explicit_ports = true;
            }
        }
        for (const skan::portscan::Port &port : excluded.ports) {
            selected_ports.erase(
                std::remove(selected_ports.begin(), selected_ports.end(), port.number),
                selected_ports.end());
        }
        if (selected_ports.empty()) {
            std::cerr << "Error: --exclude-ports removed every selected port.\n";
            return EXIT_FAILURE;
        }
    }
    if (!explicit_ports) {
        config.ports.clear();
    }
    if (output_all_prefix.has_value() && config.output_file.has_value()) {
        std::cerr << "Error: -oA cannot be combined with another output file option.\n";
        return EXIT_FAILURE;
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
    if (transport_mode == "connect") {
        config.transport = skan::orchestrator::ScanTransport::Connect;
    } else if (transport_mode == "offline") {
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
    if (config.discovery_enabled && transport_mode.empty()) {
        std::cerr << "Error: --discovery requires --transport offline or --transport linux --interface <name>.\n";
        return EXIT_FAILURE;
    }
    const bool interactive_normal_output =
        config.output_format == skan::output::OutputFormat::Normal &&
        !config.output_file.has_value() && !output_all_prefix.has_value() && ::isatty(STDOUT_FILENO) != 0;
    config.output_context.interactive_terminal = interactive_normal_output;
    config.output_context.color_enabled = interactive_normal_output && !no_color;
    const skan::target::TargetResolutionResult resolved =
        skan::target::TargetEngine::resolve(target_specification, target_limits);
    if (!resolved.success()) {
        print_target_error(resolved.error);
        return EXIT_FAILURE;
    }
    std::vector<skan::core::IpAddress> excluded_addresses;
    for (const std::string &excluded_specification : excluded_target_specifications) {
        const skan::target::TargetResolutionResult excluded =
            skan::target::TargetEngine::resolve(excluded_specification, target_limits);
        if (!excluded.success()) {
            std::cerr << "Error: invalid --exclude target specification: ";
            print_target_error(excluded.error);
            return EXIT_FAILURE;
        }
        for (const skan::target::ResolvedTarget &target : excluded.target_set.targets) {
            excluded_addresses.push_back(target.ip_address.valid()
                                             ? target.ip_address
                                             : skan::core::IpAddress::from_ipv4(target.address));
        }
    }
    std::sort(excluded_addresses.begin(), excluded_addresses.end());
    excluded_addresses.erase(
        std::unique(excluded_addresses.begin(), excluded_addresses.end()),
        excluded_addresses.end());

    skan::core::Target normalized_target;
    normalized_target.original_specification = target_specification;
    normalized_target.resolved_hosts.reserve(resolved.target_set.targets.size());
    for (const skan::target::ResolvedTarget &target : resolved.target_set.targets) {
        const skan::core::IpAddress ip_address = target.ip_address.valid()
                                                    ? target.ip_address
                                                    : skan::core::IpAddress::from_ipv4(target.address);
        if ((ipv4_only && !ip_address.is_ipv4()) || (ipv6_only && !ip_address.is_ipv6()) ||
            std::binary_search(excluded_addresses.begin(), excluded_addresses.end(), ip_address)) {
            continue;
        }
        normalized_target.resolved_hosts.push_back(
            skan::core::Host{skan::target::format_ip_address(ip_address), target.source_hostname, false, ip_address});
    }
    if (normalized_target.resolved_hosts.empty()) {
        std::cerr << "Error: target family filters and exclusions removed every resolved target.\n";
        return EXIT_FAILURE;
    }
    if (config.transport == skan::orchestrator::ScanTransport::Linux && !config.interface_name.has_value()) {
        const skan::net::InterfaceResult selected = skan::net::select_interface_for_target(normalized_target);
        if (!selected.success()) {
            std::cerr << "Error: raw interface selection failed: " << selected.message << " ("
                      << skan::net::interface_status_name(selected.status) << ").\n";
            return EXIT_FAILURE;
        }
        config.interface_name = selected.interface.name;
    }
    if (config.transport == skan::orchestrator::ScanTransport::Linux) {
        for (const skan::core::Host &host : normalized_target.resolved_hosts) {
            std::string scope_error;
            if (!validate_raw_ipv6_scope(host.ip_address, config.interface_name, scope_error)) {
                std::cerr << "Error: " << scope_error << ".\n";
                return EXIT_FAILURE;
            }
        }
    }
    config.targets.push_back(std::move(normalized_target));
    skan::orchestrator::ScanOrchestrator orchestrator(config);
    std::ostringstream suppressed_primary_output;
    std::ostream &primary_output = output_all_prefix.has_value()
                                       ? static_cast<std::ostream &>(suppressed_primary_output)
                                       : static_cast<std::ostream &>(std::cout);
    const skan::core::StatusCode status = orchestrator.run(primary_output);
    if (status != skan::core::StatusCode::Ok) {
        std::cerr << "Error: scan orchestration failed: " << skan::core::status_to_string(status);
        if (!orchestrator.session().error_message().empty()) {
            std::cerr << " (" << orchestrator.session().error_message() << ')';
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }
    if (output_all_prefix.has_value()) {
        if (!orchestrator.report().has_value()) {
            std::cerr << "Error: scan completed without a report for -oA serialization.\n";
            return EXIT_FAILURE;
        }
        const auto write_aggregate = [&](skan::output::OutputFormat format, std::string_view suffix) {
            const std::string path = *output_all_prefix + std::string(suffix);
            std::ofstream output(path, std::ios::out | std::ios::trunc);
            if (!output.is_open()) {
                return false;
            }
            skan::output::OutputContext file_context = config.output_context;
            file_context.color_enabled = false;
            file_context.interactive_terminal = false;
            return skan::output::OutputManager::write(
                       format, *orchestrator.report(), output, file_context) ==
                   skan::output::OutputStatus::Ok && output.good();
        };
        if (!write_aggregate(skan::output::OutputFormat::Normal, ".nmap") ||
            !write_aggregate(skan::output::OutputFormat::Xml, ".xml") ||
            !write_aggregate(skan::output::OutputFormat::Grepable, ".gnmap")) {
            std::cerr << "Error: failed to write one or more -oA output files.\n";
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int run_nmap_compatible(int argc, char **argv)
{
    if (argc < 2) {
        return EXIT_FAILURE;
    }
    const auto option_requires_value = [](std::string_view option) noexcept {
        return option == "--top-ports" || option == "--udp-ports" || option == "--tcp-ports" ||
               option == "-p" || option == "--method" || option == "--timeout-ms" ||
               option == "--udp-timeout-ms" || option == "--max-outstanding" ||
               option == "--udp-max-outstanding" || option == "--udp-retries" ||
               option == "--timing" || option == "--min-parallelism" ||
               option == "--max-parallelism" || option == "--retries" ||
               option == "--transport" || option == "--max-targets" ||
               option == "--max-hostname-results" || option == "--interface" ||
               option == "-e" || option == "-oN" || option == "-oX" ||
               option == "-oG" || option == "-oA" || option == "--output" ||
               option == "-o" || option == "--output-file" || option == "--service-db" ||
               option == "--max-response-bytes" || option == "--max-probes" ||
               option == "--exclude" || option == "--exclude-ports";
    };

    std::vector<std::string> options;
    std::vector<std::string> targets;
    options.reserve(static_cast<std::size_t>(argc));
    targets.reserve(static_cast<std::size_t>(argc));
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (!argument.empty() && argument.front() == '-') {
            options.emplace_back(argument);
            if (option_requires_value(argument)) {
                if (index + 1 >= argc) {
                    std::cerr << "Error: incomplete Nmap-compatible option.\n";
                    return EXIT_FAILURE;
                }
                options.emplace_back(argv[++index]);
            }
        } else {
            targets.emplace_back(argument);
        }
    }
    if (targets.empty()) {
        std::cerr << "Error: Nmap-compatible mode requires at least one target specification.\n";
        return EXIT_FAILURE;
    }
    std::string target_specification;
    for (const std::string &target : targets) {
        if (target.empty()) {
            std::cerr << "Error: target specification cannot be empty.\n";
            return EXIT_FAILURE;
        }
        if (!target_specification.empty()) {
            target_specification.push_back(',');
        }
        target_specification += target;
    }

    std::vector<std::string> normalized;
    normalized.reserve(options.size() + 3U);
    normalized.emplace_back(argv[0]);
    normalized.emplace_back("scan");
    normalized.push_back(std::move(target_specification));
    normalized.insert(normalized.end(), options.begin(), options.end());

    std::vector<char *> normalized_argv;
    normalized_argv.reserve(normalized.size());
    for (std::string &argument : normalized) {
        normalized_argv.push_back(argument.data());
    }
    return run_scan(static_cast<int>(normalized_argv.size()), normalized_argv.data());
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << skan::core::constants::SKAN_DISPLAY_VERSION << '\n';
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

    if (argc >= 2) {
        return run_nmap_compatible(argc, argv);
    }

    std::cerr << "Error: unknown or missing argument. Use --help for usage.\n";
    return EXIT_FAILURE;
}
