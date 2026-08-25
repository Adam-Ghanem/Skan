#include <cassert>
#include <string>

#include "db/os_db.hpp"

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

    const db::OSFingerprintDatabase built_in = db::OSFingerprintDatabase::built_in();
    assert(built_in.status() == core::StatusCode::Ok);
    assert(built_in.fingerprints().size() == 3U);
    return 0;
}
