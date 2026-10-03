#include <algorithm>
#include <cassert>
#include <cmath>

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

bool contains(const std::vector<std::string> &values, const std::string &needle)
{
    return std::find(values.begin(), values.end(), needle) != values.end();
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
    assert(exact_matches[0].fingerprint_name == "LinuxModern64240");
    assert(exact_matches[0].confidence >= osdetect::kPossibleMatchThreshold);
    assert(exact_matches[0].confidence < 1.0);
    assert(exact_matches[0].category == db::MatchCategory::StrongMatch);

    osdetect::ObservedOSFingerprint partial;
    osdetect::TCPObservation partial_observation;
    partial_observation.ttl = osdetect::ObservedValue<std::uint8_t>::observed(64U);
    partial_observation.probe_status = osdetect::OSProbeStatus::ResponseReceived;
    partial.tcp_observations.push_back(partial_observation);
    const auto partial_matches = matcher.match(partial, 3U);
    for (const auto &match : partial_matches) {
        assert(match.confidence < osdetect::kPossibleMatchThreshold);
        assert(match.category != db::MatchCategory::StrongMatch);
        assert(!match.unavailable_fields.empty());
    }

    osdetect::ObservedOSFingerprint mismatch;
    osdetect::TCPObservation mismatch_observation = linux_observation();
    mismatch_observation.ttl = osdetect::ObservedValue<std::uint8_t>::observed(255U);
    mismatch.tcp_observations.push_back(mismatch_observation);
    const auto mismatch_matches = matcher.match(mismatch, database.fingerprints().size());
    const auto mismatch_match = std::find_if(
        mismatch_matches.begin(), mismatch_matches.end(), [](const osdetect::OSMatchResult &match) {
            return match.fingerprint_id == "skan-v4-linux-modern-64240";
        });
    assert(mismatch_match != mismatch_matches.end());
    assert(mismatch_match->confidence < 1.0);
    assert(!mismatch_match->mismatched_fields.empty());

    // ACK/sequence behavior currently has no probe provenance in the observation
    // model. It must therefore fail closed as unavailable instead of scoring the
    // first TCP response (normally a SYN/SYN-ACK) against behavior that may have
    // been defined for a different probe class.
    core::StatusCode behavior_status = core::StatusCode::InternalError;
    const db::OSFingerprintDatabase behavior_database = db::OSFingerprintDatabase::parse(
        "Fingerprint ProbeScopedBehavior\n"
        "ID=probe-scoped-behavior\n"
        "SPECIFICITY=3\n"
        "ADDRESS_FAMILY=IPv4\n"
        "Class Test | Test\n"
        "TTL=64\n"
        "ACK_BEHAVIOR=RST_WITHOUT_ACK\n"
        "SEQUENCE_BEHAVIOR=RANDOMIZED\n",
        behavior_status,
        core::AddressFamily::IPv4);
    assert(behavior_status == core::StatusCode::Ok);
    osdetect::OSMatcher behavior_matcher(behavior_database);
    osdetect::ObservedOSFingerprint ambiguous_behavior;
    auto syn_observation = linux_observation();
    syn_observation.ack_behavior = osdetect::AckBehavior::AcknowledgesSyn;
    syn_observation.sequence_behavior = osdetect::SequenceBehavior::Zero;
    ambiguous_behavior.tcp_observations.push_back(std::move(syn_observation));
    const auto behavior_matches = behavior_matcher.match(ambiguous_behavior, 1U);
    assert(behavior_matches.size() == 1U);
    assert(std::abs(behavior_matches[0].confidence - 0.5) < 1e-12);
    assert(behavior_matches[0].category == db::MatchCategory::LowConfidence);
    assert(contains(behavior_matches[0].matched_fields, "TTL"));
    assert(contains(behavior_matches[0].unavailable_fields, "ACK_BEHAVIOR"));
    assert(contains(behavior_matches[0].unavailable_fields, "SEQUENCE_BEHAVIOR"));
    assert(!contains(behavior_matches[0].mismatched_fields, "ACK_BEHAVIOR"));
    assert(!contains(behavior_matches[0].mismatched_fields, "SEQUENCE_BEHAVIOR"));

    osdetect::ObservedOSFingerprint unavailable;
    const auto unavailable_matches = matcher.match(unavailable, 2U);
    assert(unavailable_matches.size() == 2U);
    assert(unavailable_matches[0].confidence == 0.0);
    assert(unavailable_matches[0].category == db::MatchCategory::NoMatch);
    assert(unavailable_matches[0].specificity >= unavailable_matches[1].specificity);

    osdetect::ObservedOSFingerprint ipv6;
    ipv6.family = core::AddressFamily::IPv6;
    auto ipv6_observation = linux_observation();
    ipv6_observation.family = core::AddressFamily::IPv6;
    ipv6_observation.mss = osdetect::ObservedValue<std::uint16_t>::observed(1440U);
    ipv6.tcp_observations.push_back(ipv6_observation);
    const auto ipv6_matches = matcher.match(ipv6, 3U);
    assert(!ipv6_matches.empty());
    assert(ipv6_matches[0].fingerprint_name == "IPv6LinuxModern64240");
    assert(ipv6_matches[0].fingerprint_id == "skan-v6-linux-modern-64240");
    assert(ipv6_matches[0].address_family == core::AddressFamily::IPv6);
    assert(ipv6_matches[0].category == db::MatchCategory::StrongMatch);

    // The same sparse-evidence policy applies to IPv6, including invalid fields.
    osdetect::ObservedOSFingerprint partial_ipv6;
    partial_ipv6.family = core::AddressFamily::IPv6;
    partial_observation.family = core::AddressFamily::IPv6;
    partial_observation.window.state = osdetect::ObservationState::Invalid;
    partial_observation.timestamps.state = osdetect::ObservationState::TimedOut;
    partial_ipv6.tcp_observations.push_back(partial_observation);
    const auto partial_ipv6_matches = matcher.match(partial_ipv6, database.fingerprints().size());
    assert(!partial_ipv6_matches.empty());
    for (const auto &match : partial_ipv6_matches) {
        assert(match.confidence < osdetect::kPossibleMatchThreshold);
        assert(match.category != db::MatchCategory::StrongMatch);
    }

    // Missing required evidence lowers support; adding valid evidence raises it.
    core::StatusCode coverage_status = core::StatusCode::InternalError;
    const auto coverage_database = db::OSFingerprintDatabase::parse(
        "Fingerprint Coverage\nID=coverage\nSPECIFICITY=9\nADDRESS_FAMILY=IPv4\n"
        "Class Test | Coverage\nTTL=64\nWINDOW=64240\nMSS=1460\nSACK=Y\nTIMESTAMP=Y\n",
        coverage_status, core::AddressFamily::IPv4);
    assert(coverage_status == core::StatusCode::Ok);
    osdetect::OSMatcher coverage_matcher(coverage_database);
    partial_observation.family = core::AddressFamily::IPv4;
    osdetect::ObservedOSFingerprint coverage;
    coverage.tcp_observations.push_back(partial_observation);
    const auto sparse_score = coverage_matcher.match(coverage, 1U).front();
    assert(sparse_score.confidence < osdetect::kNoMatchThreshold);
    assert(sparse_score.category == db::MatchCategory::NoMatch);
    coverage.tcp_observations.front().window = osdetect::ObservedValue<std::uint16_t>::observed(64240U);
    const auto improved_score = coverage_matcher.match(coverage, 1U).front();
    assert(improved_score.confidence > sparse_score.confidence);
    assert(improved_score.confidence < 1.0);
    coverage.tcp_observations.front() = linux_observation();
    assert(coverage_matcher.match(coverage, 1U).front().confidence == 1.0);
    coverage.tcp_observations.front().mss.value = 1200U;
    const auto contradicted = coverage_matcher.match(coverage, 1U).front();
    assert(contradicted.confidence < 1.0);
    assert(contains(contradicted.mismatched_fields, "MSS"));

    // A broad fully matched fallback does not displace a strongly supported
    // specific profile merely because one secondary field is unavailable.
    const auto ranking_database = db::OSFingerprintDatabase::parse(
        "Fingerprint Broad\nID=broad\nSPECIFICITY=2\nADDRESS_FAMILY=IPv4\n"
        "Class Generic | Generic\nTTL=64\nWINDOW=64240\n"
        "Fingerprint Specific\nID=specific\nSPECIFICITY=9\nADDRESS_FAMILY=IPv4\n"
        "Class Test | Specific\nTTL=64\nWINDOW=64240\nMSS=1460\nSACK=Y\nTIMESTAMP=Y\nDF=Y\n",
        coverage_status, core::AddressFamily::IPv4);
    assert(coverage_status == core::StatusCode::Ok);
    auto ranking_observation = linux_observation();
    ranking_observation.dont_fragment = osdetect::ObservedValue<bool>::absent();
    osdetect::ObservedOSFingerprint ranking;
    ranking.tcp_observations.push_back(ranking_observation);
    const auto ranked = osdetect::OSMatcher(ranking_database).match(ranking, 2U);
    assert(ranked.size() == 2U);
    assert(ranked.front().fingerprint_id == "specific");
    assert(ranked.front().category == db::MatchCategory::StrongMatch);
    assert(ranked.front().confidence < ranked.back().confidence);
    ranking.tcp_observations.front().mss.value = 1200U;
    const auto weakened = osdetect::OSMatcher(ranking_database).match(ranking, 2U);
    assert(weakened.front().fingerprint_id == "broad");
    assert(weakened.front().category == db::MatchCategory::StrongMatch);
    assert(weakened.back().category != db::MatchCategory::StrongMatch);

    osdetect::ObservedOSFingerprint mixed;
    mixed.family = core::AddressFamily::Unknown;
    mixed.tcp_observations.push_back(linux_observation());
    auto mixed_ipv6 = linux_observation();
    mixed_ipv6.family = core::AddressFamily::IPv6;
    mixed.tcp_observations.push_back(mixed_ipv6);
    assert(matcher.match(mixed, 3U).empty());
    return 0;
}
