#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

#include "core/status.hpp"
#include "db/db_types.hpp"
#include "db/os_db.hpp"
#include "detect/service_db.hpp"
#include "detect/service_matcher.hpp"
#include "portscan/udp_scan.hpp"

namespace {

int fail(const std::string_view message)
{
    std::cerr << "compiled runtime gate: " << message << '\n';
    return 1;
}

const skan::detect::ServiceProbeDefinition *find_service_probe(
    const skan::detect::ServiceProbeDatabase &database,
    const std::string_view name)
{
    for (const auto &probe : database.probes()) {
        if (probe.name == name) {
            return &probe;
        }
    }
    return nullptr;
}

const skan::db::OSFingerprint *find_fingerprint(
    const skan::db::OSFingerprintDatabase &database,
    const std::string_view id)
{
    for (const auto &fingerprint : database.fingerprints()) {
        if (fingerprint.id == id) {
            return &fingerprint;
        }
    }
    return nullptr;
}

bool has_number_signature(
    const skan::db::OSFingerprint &fingerprint,
    const skan::db::FingerprintField field,
    const std::int64_t value)
{
    for (const auto &signature : fingerprint.signatures) {
        if (signature.field == field && signature.number == value) {
            return true;
        }
    }
    return false;
}

bool has_boolean_signature(
    const skan::db::OSFingerprint &fingerprint,
    const skan::db::FingerprintField field,
    const bool value)
{
    for (const auto &signature : fingerprint.signatures) {
        if (signature.field == field && signature.boolean == value) {
            return true;
        }
    }
    return false;
}

bool has_range_signature(
    const skan::db::OSFingerprint &fingerprint,
    const skan::db::FingerprintField field,
    const std::int64_t minimum,
    const std::int64_t maximum)
{
    for (const auto &signature : fingerprint.signatures) {
        if (signature.field == field && signature.minimum == minimum &&
            signature.maximum == maximum) {
            return true;
        }
    }
    return false;
}

bool has_port_hint(
    const skan::detect::ServiceProbeDefinition &probe,
    const std::uint16_t port)
{
    for (const auto &hint : probe.port_hints) {
        if (hint.number == port && hint.protocol == skan::portscan::Protocol::Tcp) {
            return true;
        }
    }
    return false;
}

bool has_fallback(const skan::detect::ServiceProbeDefinition &probe, const std::string_view name)
{
    for (const auto &fallback : probe.fallback_probe_names) {
        if (fallback == name) {
            return true;
        }
    }
    return false;
}

bool has_service_rule(
    const skan::detect::ServiceProbeDefinition &probe,
    const skan::detect::ServiceMatchType type,
    const std::string_view pattern,
    const std::string_view service,
    const std::string_view product,
    const std::string_view version)
{
    for (const auto &rule : probe.rules) {
        if (rule.type == type && rule.pattern == pattern && rule.service == service &&
            rule.product == product && rule.version == version) {
            return true;
        }
    }
    return false;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "usage: test_compiled_runtime GENERATED_DIRECTORY\n";
        return 64;
    }
    const std::filesystem::path directory(argv[1]);

    skan::core::StatusCode service_status = skan::core::StatusCode::InternalError;
    const auto service = skan::detect::ServiceProbeDatabase::load_file(
        (directory / "service-probes.db").string(), service_status);
    if (service_status != skan::core::StatusCode::Ok || service.probes().size() != 40U) {
        return fail("service probe loader or count mismatch");
    }
    std::size_t service_rules = 0U;
    for (const auto &probe : service.probes()) {
        service_rules += probe.rules.size();
    }
    if (service_rules != 145U) {
        return fail("service rule count mismatch");
    }
    const auto *ssh = find_service_probe(service, "SSHBanner");
    if (ssh == nullptr) {
        return fail("SSHBanner probe is missing");
    }
    if (ssh->protocol != skan::portscan::Protocol::Tcp || ssh->payload != "\r\n" ||
        ssh->rarity != 1U || ssh->priority != 100U || !ssh->timeout.has_value() ||
        *ssh->timeout != std::chrono::milliseconds(1400) || !has_port_hint(*ssh, 22U) ||
        !has_fallback(*ssh, "GenericBanner") || !has_fallback(*ssh, "HTTPGet")) {
        return fail("SSHBanner probe semantics mismatch");
    }
    bool has_openssh = false;
    for (const auto &rule : ssh->rules) {
        has_openssh = has_openssh ||
                      (rule.type == skan::detect::ServiceMatchType::Regex &&
                       rule.service == "ssh" && rule.product == "OpenSSH" &&
                       rule.pattern == "^SSH-([0-9.]+)-OpenSSH_([0-9A-Za-z.p+_-]+)");
    }
    if (!has_openssh) {
        return fail("SSH/OpenSSH matcher is missing");
    }

    const auto *nntp = find_service_probe(service, "NNTPCapabilities");
    if (nntp == nullptr || nntp->protocol != skan::portscan::Protocol::Tcp ||
        nntp->payload != "CAPABILITIES\r\n" || !has_port_hint(*nntp, 119U) ||
        !has_fallback(*nntp, "GenericBanner") ||
        !has_service_rule(
            *nntp,
            skan::detect::ServiceMatchType::Regex,
            "^(?:20[01][^\r\n]*\r?\n)?101[^\r\n]*\r?\n[\\s\\S]*VERSION ([0-9]+)\r?\n",
            "nntp",
            "NNTP",
            "$1")) {
        return fail("NNTP probe semantics mismatch");
    }

    const auto *socks5 = find_service_probe(service, "SOCKS5Greeting");
    if (socks5 == nullptr || socks5->protocol != skan::portscan::Protocol::Tcp ||
        socks5->payload != std::string("\x05\x01\x00", 3U) ||
        !has_port_hint(*socks5, 1080U) || !has_port_hint(*socks5, 1081U) ||
        !has_fallback(*socks5, "GenericBanner") ||
        !has_service_rule(
            *socks5,
            skan::detect::ServiceMatchType::Exact,
            std::string("\x05\x00", 2U),
            "socks5",
            "SOCKS",
            "5")) {
        return fail("SOCKS5 probe semantics mismatch");
    }

    const auto *ajp13 = find_service_probe(service, "AJP13CPing");
    if (ajp13 == nullptr || ajp13->protocol != skan::portscan::Protocol::Tcp ||
        ajp13->payload != std::string("\x12\x34\x00\x01\x0a", 5U) ||
        !has_port_hint(*ajp13, 8009U) || !has_fallback(*ajp13, "GenericBanner") ||
        !has_service_rule(
            *ajp13,
            skan::detect::ServiceMatchType::Exact,
            std::string("\x41\x42\x00\x01\x09", 5U),
            "ajp13",
            "Apache-JServ-Protocol",
            "1.3")) {
        return fail("AJP13 probe semantics mismatch");
    }

    const auto *rsync = find_service_probe(service, "RsyncGreeting");
    if (rsync == nullptr || rsync->protocol != skan::portscan::Protocol::Tcp ||
        !rsync->payload.empty() || !has_port_hint(*rsync, 873U) ||
        !has_fallback(*rsync, "GenericBanner") ||
        !has_service_rule(
            *rsync,
            skan::detect::ServiceMatchType::Regex,
            "^@RSYNCD: ([0-9]+\\.[0-9]+)\r?\n",
            "rsync",
            "rsyncd",
            "$1")) {
        return fail("rsync probe semantics mismatch");
    }

    const skan::detect::ServiceMatcher service_matcher(service);
    const auto nntp_match = service_matcher.match(
        *nntp,
        "200 news.example ready\r\n101 Capability list:\r\nVERSION 2\r\n.\r\n");
    if (!nntp_match.matched || nntp_match.strength != skan::detect::ServiceMatchStrength::Hard ||
        nntp_match.service != "nntp" || nntp_match.product != "NNTP" ||
        nntp_match.version != "2" || nntp_match.confidence < 0.99) {
        return fail("NNTP compiled matcher mismatch");
    }
    const auto socks5_match = service_matcher.match(*socks5, std::string("\x05\x00", 2U));
    if (!socks5_match.matched ||
        socks5_match.strength != skan::detect::ServiceMatchStrength::Hard ||
        socks5_match.service != "socks5" || socks5_match.product != "SOCKS" ||
        socks5_match.version != "5" || socks5_match.extra != "no-authentication" ||
        socks5_match.confidence < 0.99) {
        return fail("SOCKS5 compiled matcher mismatch");
    }
    const auto ajp13_match =
        service_matcher.match(*ajp13, std::string("\x41\x42\x00\x01\x09", 5U));
    if (!ajp13_match.matched ||
        ajp13_match.strength != skan::detect::ServiceMatchStrength::Hard ||
        ajp13_match.service != "ajp13" ||
        ajp13_match.product != "Apache-JServ-Protocol" || ajp13_match.version != "1.3" ||
        ajp13_match.confidence < 0.99) {
        return fail("AJP13 compiled matcher mismatch");
    }
    const auto rsync_match = service_matcher.match(*rsync, "@RSYNCD: 31.0\n");
    if (!rsync_match.matched ||
        rsync_match.strength != skan::detect::ServiceMatchStrength::Hard ||
        rsync_match.service != "rsync" || rsync_match.product != "rsyncd" ||
        rsync_match.version != "31.0" || rsync_match.confidence < 0.99) {
        return fail("rsync compiled matcher mismatch");
    }

    skan::core::StatusCode udp_status = skan::core::StatusCode::InternalError;
    const auto udp = skan::portscan::UDPProbeDatabase::load_file(
        (directory / "udp-probes.db").string(), udp_status);
    if (udp_status != skan::core::StatusCode::Ok || udp.definitions().size() != 21U) {
        return fail("UDP loader or count mismatch");
    }
    const auto *dns = udp.for_port(53U);
    const std::vector<std::uint8_t> expected_dns_payload{
        0x53U, 0x4bU, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x04U, 0x73U, 0x6bU, 0x61U, 0x6eU, 0x07U, 0x69U, 0x6eU,
        0x76U, 0x61U, 0x6cU, 0x69U, 0x64U, 0x00U, 0x00U, 0x01U, 0x00U, 0x01U};
    const auto &default_probe = udp.default_probe();
    if (dns == nullptr || dns->name != "DNS" || dns->destination_port != 53U ||
        dns->protocol_hint != "dns" || dns->max_response_bytes != 4096U ||
        dns->payload != expected_dns_payload || default_probe.name != "DEFAULT" ||
        default_probe.destination_port != 0U || default_probe.protocol_hint != "generic" ||
        default_probe.max_response_bytes != 512U ||
        default_probe.payload != std::vector<std::uint8_t>{0x00U}) {
        return fail("DNS or DEFAULT UDP probe mismatch");
    }

    skan::core::StatusCode ipv4_status = skan::core::StatusCode::InternalError;
    const auto ipv4 = skan::db::OSFingerprintDatabase::load_file(
        (directory / "os-fingerprints.db").string(), ipv4_status,
        skan::core::AddressFamily::IPv4);
    if (ipv4_status != skan::core::StatusCode::Ok || ipv4.fingerprints().size() != 27U) {
        return fail("IPv4 OS loader or count mismatch");
    }
    const auto *linux4 = find_fingerprint(ipv4, "skan-v4-linux-modern-64240");
    if (linux4 == nullptr || linux4->address_family != skan::core::AddressFamily::IPv4 ||
        linux4->specificity != 18U ||
        !has_range_signature(*linux4, skan::db::FingerprintField::Ttl, 45, 64) ||
        !has_number_signature(*linux4, skan::db::FingerprintField::Window, 64240) ||
        !has_number_signature(*linux4, skan::db::FingerprintField::Mss, 1460) ||
        !has_boolean_signature(*linux4, skan::db::FingerprintField::DontFragment, true)) {
        return fail("modern Linux IPv4 typed semantics mismatch");
    }

    skan::core::StatusCode ipv6_status = skan::core::StatusCode::InternalError;
    const auto ipv6 = skan::db::OSFingerprintDatabase::load_file(
        (directory / "os-fingerprints-v6.db").string(), ipv6_status,
        skan::core::AddressFamily::IPv6);
    if (ipv6_status != skan::core::StatusCode::Ok || ipv6.fingerprints().size() != 24U) {
        return fail("IPv6 OS loader or count mismatch");
    }
    const auto *linux6 = find_fingerprint(ipv6, "skan-v6-linux-modern-64240");
    if (linux6 == nullptr || linux6->address_family != skan::core::AddressFamily::IPv6 ||
        linux6->specificity != 17U ||
        !has_range_signature(*linux6, skan::db::FingerprintField::Ttl, 45, 64) ||
        !has_number_signature(*linux6, skan::db::FingerprintField::Window, 64240) ||
        !has_number_signature(*linux6, skan::db::FingerprintField::Mss, 1440)) {
        return fail("modern Linux IPv6 typed semantics mismatch");
    }
    return 0;
}
