#include <cassert>
#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

#include "db/os_db.hpp"

namespace {

const skan::db::OSFingerprint *find_by_id(
    const std::vector<skan::db::OSFingerprint> &fingerprints,
    const std::string &id)
{
    for (const skan::db::OSFingerprint &fingerprint : fingerprints) {
        if (fingerprint.id == id) {
            return &fingerprint;
        }
    }
    return nullptr;
}

struct CorpusSummary final {
    std::size_t ipv4_count{0U};
    std::size_t ipv6_count{0U};
};

CorpusSummary validate_corpus(const std::vector<skan::db::OSFingerprint> &fingerprints)
{
    assert(!fingerprints.empty());
    std::unordered_set<std::string> names;
    std::unordered_set<std::string> ids;
    CorpusSummary summary;
    for (const skan::db::OSFingerprint &fingerprint : fingerprints) {
        assert(!fingerprint.name.empty());
        assert(!fingerprint.id.empty());
        assert(!fingerprint.vendor.empty());
        assert(!fingerprint.family.empty());
        assert(!fingerprint.signatures.empty());
        assert(names.insert(fingerprint.name).second);
        assert(ids.insert(fingerprint.id).second);
        if (fingerprint.address_family == skan::core::AddressFamily::IPv4) {
            ++summary.ipv4_count;
        } else if (fingerprint.address_family == skan::core::AddressFamily::IPv6) {
            ++summary.ipv6_count;
        } else {
            assert(false);
        }
    }
    return summary;
}

} // namespace

int main()
{
    using namespace skan;
    const std::string text =
        "# owned test data\n\n"
        "Fingerprint Alpha\n"
        "Class Skan | TestOS | 1 | appliance\n"
        "TTL=64\n"
        "DF=Y\n"
        "TCP_OPTIONS=MSS,NOP,WS\n"
        "RESPONSE_BEHAVIOR=RST\n"
        "WINDOW_RANGE=32-65535\n"
        "UDP_PAYLOAD_RANGE=0-512\n"
        "UDP_RESPONSE_BEHAVIOR=PORT_UNREACHABLE\n"
        "RESPONSE_PRESENCE=YES\n\n"
        "Fingerprint Beta\n"
        "Class Skan | TestOS | 2 | appliance\n"
        "TTL=128\n"
        "WINDOW=65535\n"
        "RESPONSE_BEHAVIOR=SYN_ACK\n";
    core::StatusCode status = core::StatusCode::InternalError;
    const db::OSFingerprintDatabase database = db::OSFingerprintDatabase::parse(text, status);
    assert(status == core::StatusCode::Ok);
    assert(database.status() == core::StatusCode::Ok);
    assert(database.fingerprints().size() == 2U);
    assert(database.fingerprints()[0].name == "Alpha");
    assert(database.fingerprints()[1].name == "Beta");
    assert(database.fingerprints()[0].signatures.size() == 8U);
    const db::OSFingerprintDatabase optional_class = db::OSFingerprintDatabase::parse(
        "Fingerprint Optional\nClass Skan | Minimal\nTTL_RANGE=32-64\n", status);
    assert(status == core::StatusCode::Ok);
    assert(optional_class.fingerprints().size() == 1U);
    assert(optional_class.fingerprints()[0].generation.empty());
    assert(optional_class.fingerprints()[0].device_type.empty());

    const std::string duplicate_signature =
        "Fingerprint Broken\nClass Skan | Test | 1 | device\nTTL=64\nTTL=128\n";
    const db::OSFingerprintDatabase duplicate = db::OSFingerprintDatabase::parse(duplicate_signature, status);
    assert(status == core::StatusCode::ParseError);
    assert(duplicate.fingerprints().empty());

    const db::OSFingerprintDatabase missing_class = db::OSFingerprintDatabase::parse(
        "Fingerprint Broken\nTTL=64\n", status);
    assert(status == core::StatusCode::ParseError);
    assert(missing_class.fingerprints().empty());

    const db::OSFingerprintDatabase bad_value = db::OSFingerprintDatabase::parse(
        "Fingerprint Broken\nClass Skan | Test | 1 | device\nTTL=not-a-number\n", status);
    assert(status == core::StatusCode::ParseError);
    assert(bad_value.fingerprints().empty());

    const db::OSFingerprintDatabase bad_range = db::OSFingerprintDatabase::parse(
        "Fingerprint Broken\nClass Skan | Test | 1 | device\nTTL_RANGE=64-32\n", status);
    assert(status == core::StatusCode::ParseError);
    assert(bad_range.fingerprints().empty());

    std::string oversized(1024U * 1024U + 1U, 'x');
    const db::OSFingerprintDatabase oversized_database = db::OSFingerprintDatabase::parse(oversized, status);
    assert(status == core::StatusCode::ParseError);
    assert(oversized_database.fingerprints().empty());

    const db::OSFingerprintDatabase unsupported = db::OSFingerprintDatabase::parse(
        "Fingerprint Broken\nClass Skan | Test | 1 | device\nMADE_UP=1\n", status);
    assert(status == core::StatusCode::ParseError);
    assert(unsupported.fingerprints().empty());

    const db::OSFingerprintDatabase duplicate_name = db::OSFingerprintDatabase::parse(
        "Fingerprint Same\nClass Skan | Test | 1 | device\nTTL=64\n"
        "Fingerprint Same\nClass Skan | Test | 2 | device\nTTL=128\n", status);
    assert(status == core::StatusCode::ParseError);
    assert(duplicate_name.fingerprints().empty());

    const db::OSFingerprintDatabase missing = db::OSFingerprintDatabase::load_file(
        "/tmp/skan-phase6-no-such-fingerprint-db", status);
    assert(status == core::StatusCode::NotFound);
    assert(missing.status() == core::StatusCode::NotFound);

    const db::OSFingerprintDatabase ipv6 = db::OSFingerprintDatabase::parse(
        "Fingerprint IPv6Only\nID=test-v6\nSPECIFICITY=7\nADDRESS_FAMILY=IPv6\n"
        "Class Skan | IPv6 | test | appliance\nTTL=64\nWINDOW=64240\nRESPONSE_BEHAVIOR=SYN_ACK\n",
        status, core::AddressFamily::IPv6);
    assert(status == core::StatusCode::Ok);
    assert(ipv6.fingerprints().size() == 1U);
    assert(ipv6.fingerprints()[0].address_family == core::AddressFamily::IPv6);
    assert(ipv6.fingerprints()[0].id == "test-v6");
    assert(ipv6.fingerprints()[0].specificity == 7U);
    const db::OSFingerprintDatabase missing_ipv6_family = db::OSFingerprintDatabase::parse(
        "Fingerprint Broken\nClass Skan | IPv6 | test\nTTL=64\n", status, core::AddressFamily::IPv6);
    assert(status == core::StatusCode::ParseError);
    assert(missing_ipv6_family.fingerprints().empty());

    const db::OSFingerprintDatabase built_in = db::OSFingerprintDatabase::built_in();
    assert(built_in.status() == core::StatusCode::Ok);
    const CorpusSummary summary = validate_corpus(built_in.fingerprints());
    assert(summary.ipv4_count > 0U);
    assert(summary.ipv6_count > 0U);
    const db::OSFingerprint *ipv4_representative = find_by_id(
        built_in.fingerprints(), "skan-v4-linux-modern-64240");
    assert(ipv4_representative != nullptr);
    assert(ipv4_representative->address_family == core::AddressFamily::IPv4);
    const db::OSFingerprint *ipv6_representative = find_by_id(
        built_in.fingerprints(), "skan-v6-linux-modern-64240");
    assert(ipv6_representative != nullptr);
    assert(ipv6_representative->address_family == core::AddressFamily::IPv6);
    return 0;
}
