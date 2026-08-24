#include <cassert>

#include "db/os_db.hpp"
#include "osdetect/os_matcher.hpp"

namespace {

skan::osdetect::TCPObservation linux_observation()
{
    using namespace skan;
    osdetect::TCPObservation observation;
    observation.ttl = osdetect::ObservedValue<std::uint8_t>::observed(64U);
    observation.dont_fragment = osdetect::ObservedValue<bool>::observed(true);
    observation.window = osdetect::ObservedValue<std::uint16_t>::observed(64240U);
    observation.mss = osdetect::ObservedValue<std::uint16_t>::observed(1460U);
    observation.window_scale = osdetect::ObservedValue<std::uint8_t>::observed(7U);
    observation.sack_permitted = osdetect::ObservedValue<bool>::observed(true);
    observation.timestamps = osdetect::ObservedValue<bool>::observed(true);
    observation.options = {packet::TcpOptionKind::Mss, packet::TcpOptionKind::SackPermitted,
                           packet::TcpOptionKind::Timestamp, packet::TcpOptionKind::Nop,
                           packet::TcpOptionKind::WindowScale};
    observation.response_behavior = osdetect::ResponseBehavior::SynAck;
    observation.probe_status = osdetect::OSProbeStatus::ResponseReceived;
    return observation;
}

} // namespace

int main()
{
    using namespace skan;
    const db::OSFingerprintDatabase database = db::OSFingerprintDatabase::built_in();
    assert(database.status() == core::StatusCode::Ok);
    osdetect::OSMatcher matcher(database);

    osdetect::ObservedOSFingerprint exact;
    exact.tcp_observations.push_back(linux_observation());
    const auto exact_matches = matcher.match(exact, 3U);
    assert(exact_matches.size() == 3U);
    assert(exact_matches[0].fingerprint_name == "SkanLinuxGeneric");
    assert(exact_matches[0].confidence == 1.0);
    assert(exact_matches[0].category == db::MatchCategory::StrongMatch);

    osdetect::ObservedOSFingerprint partial;
    osdetect::TCPObservation partial_observation;
    partial_observation.ttl = osdetect::ObservedValue<std::uint8_t>::observed(64U);
    partial_observation.probe_status = osdetect::OSProbeStatus::ResponseReceived;
    partial.tcp_observations.push_back(partial_observation);
    const auto partial_matches = matcher.match(partial, 3U);
    assert(partial_matches[0].fingerprint_name == "SkanEmbeddedGeneric");
    assert(partial_matches[0].confidence == 1.0);
    assert(partial_matches[0].unavailable_fields.size() >= 8U);

    osdetect::ObservedOSFingerprint mismatch;
    osdetect::TCPObservation mismatch_observation = linux_observation();
    mismatch_observation.ttl = osdetect::ObservedValue<std::uint8_t>::observed(255U);
    mismatch.tcp_observations.push_back(mismatch_observation);
    const auto mismatch_matches = matcher.match(mismatch, 3U);
    assert(mismatch_matches[0].confidence < 1.0);
    assert(!mismatch_matches[0].mismatched_fields.empty());

    osdetect::ObservedOSFingerprint unavailable;
    const auto unavailable_matches = matcher.match(unavailable, 2U);
    assert(unavailable_matches.size() == 2U);
    assert(unavailable_matches[0].confidence == 0.0);
    assert(unavailable_matches[0].category == db::MatchCategory::NoMatch);
    assert(unavailable_matches[0].fingerprint_name < unavailable_matches[1].fingerprint_name);
    return 0;
}
