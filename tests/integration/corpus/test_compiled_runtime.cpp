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
    if (service_status != skan::core::StatusCode::Ok || service.probes().size() != 36U) {
        return fail("service probe loader or count mismatch");
    }
    std::size_t service_rules = 0U;
    for (const auto &probe : service.probes()) {
        service_rules += probe.rules.size();
    }
    if (service_rules != 136U) {
        return fail("service rule count mismatch");
    }
    const auto *ssh = find_service_probe(service, "SSHBanner");
    if (ssh == nullptr) {
        return fail("SSHBanner probe is missing");
    }
    if (ssh->protocol != skan::portscan::Protocol::Tcp || ssh->payload != "\r\n" ||
        ssh->rarity != 1U || ssh->priority != 100U || !ssh->timeout.has_value() ||
        *ssh->timeout != std::chrono::milliseconds(1400) || !has_port_hint(*ssh, 22U) ||
        !has_fallback(*ssh, "GenericBanner")) {
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
