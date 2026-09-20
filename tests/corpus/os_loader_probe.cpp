#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "db/os_db.hpp"

namespace {

bool same_signature(
    const skan::db::FingerprintSignature &left,
    const skan::db::FingerprintSignature &right)
{
    return left.field == right.field && left.number == right.number &&
           left.minimum == right.minimum && left.maximum == right.maximum &&
           left.boolean == right.boolean && left.text == right.text &&
           left.options == right.options;
}

bool same_fingerprint(
    skan::db::OSFingerprint left,
    skan::db::OSFingerprint right)
{
    if (left.name != right.name || left.vendor != right.vendor ||
        left.family != right.family || left.generation != right.generation ||
        left.device_type != right.device_type ||
        left.address_family != right.address_family || left.id != right.id ||
        left.specificity != right.specificity ||
        left.signatures.size() != right.signatures.size()) {
        return false;
    }
    const auto by_field = [](const skan::db::FingerprintSignature &first,
                             const skan::db::FingerprintSignature &second) {
        return static_cast<unsigned int>(first.field) <
               static_cast<unsigned int>(second.field);
    };
    std::sort(left.signatures.begin(), left.signatures.end(), by_field);
    std::sort(right.signatures.begin(), right.signatures.end(), by_field);
    for (std::size_t index = 0U; index < left.signatures.size(); ++index) {
        if (!same_signature(left.signatures[index], right.signatures[index])) {
            return false;
        }
    }
    return true;
}

skan::core::AddressFamily parse_family(const std::string &value)
{
    if (value == "ipv4") {
        return skan::core::AddressFamily::IPv4;
    }
    if (value == "ipv6") {
        return skan::core::AddressFamily::IPv6;
    }
    return skan::core::AddressFamily::Unknown;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: os_loader_probe FAMILY LEGACY GENERATED\n";
        return 2;
    }
    const skan::core::AddressFamily family = parse_family(argv[1]);
    if (family == skan::core::AddressFamily::Unknown) {
        std::cerr << "FAMILY must be ipv4 or ipv6\n";
        return 3;
    }

    skan::core::StatusCode legacy_status = skan::core::StatusCode::InternalError;
    skan::core::StatusCode generated_status = skan::core::StatusCode::InternalError;
    const auto legacy = skan::db::OSFingerprintDatabase::load_file(
        argv[2], legacy_status, family);
    const auto generated = skan::db::OSFingerprintDatabase::load_file(
        argv[3], generated_status, family);
    if (legacy_status != skan::core::StatusCode::Ok ||
        generated_status != skan::core::StatusCode::Ok) {
        std::cerr << "production OS loader rejected an input corpus\n";
        return 4;
    }

    std::vector<skan::db::OSFingerprint> legacy_fingerprints = legacy.fingerprints();
    std::vector<skan::db::OSFingerprint> generated_fingerprints = generated.fingerprints();
    if (legacy_fingerprints.size() != generated_fingerprints.size()) {
        std::cerr << "fingerprint count mismatch\n";
        return 5;
    }
    const auto by_identity = [](const skan::db::OSFingerprint &first,
                                const skan::db::OSFingerprint &second) {
        if (first.id != second.id) {
            return first.id < second.id;
        }
        return first.name < second.name;
    };
    std::sort(legacy_fingerprints.begin(), legacy_fingerprints.end(), by_identity);
    std::sort(generated_fingerprints.begin(), generated_fingerprints.end(), by_identity);

    for (std::size_t index = 0U; index < legacy_fingerprints.size(); ++index) {
        if (!same_fingerprint(legacy_fingerprints[index], generated_fingerprints[index])) {
            std::cerr << "OS semantic mismatch at identity "
                      << legacy_fingerprints[index].id << "\n";
            return 6;
        }
    }
    return 0;
}
