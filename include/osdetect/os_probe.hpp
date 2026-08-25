#ifndef SKAN_OSDETECT_OS_PROBE_HPP
#define SKAN_OSDETECT_OS_PROBE_HPP

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "io/io_engine.hpp"
#include "osdetect/os_fingerprint.hpp"
#include "osdetect/os_probe_types.hpp"

namespace skan::osdetect {

using OSProbeId = std::uint64_t;
using OSProbeClock = std::chrono::steady_clock;
using OSProbeTimePoint = OSProbeClock::time_point;

struct OSProbeConfig final {
    std::chrono::milliseconds timeout{1000};
    std::uint16_t probe_port{80U};
    std::string source_address{"192.0.2.254"};
    std::uint16_t udp_probe_port{161U};
    std::vector<std::uint8_t> udp_probe_payload{0x53U, 0x4BU, 0x41U, 0x4EU};
};

struct OSProbeSubmission final {
    OSProbeId id{0U};
    OSProbeType type{OSProbeType::TcpSynStandard};
    std::string target;
    std::string source_address;
    std::uint16_t destination_port{0U};
    std::uint16_t source_port{0U};
    std::uint32_t sequence_number{0U};
    std::uint16_t correlation_identifier{0U};
    std::uint16_t correlation_sequence{0U};
    std::vector<std::uint8_t> bytes;
    OSProbeStatus status{OSProbeStatus::Generated};
    OSProbeTimePoint generated_at{};
    core::IpAddress source_ip{};
    core::IpAddress target_ip{};
};

struct OSProbeResponse final {
    OSProbeId id{0U};
    std::string source_address;
    std::string destination_address;
    OSProbeResponseKind kind{OSProbeResponseKind::Data};
    int error_number{0};
    std::vector<std::uint8_t> bytes;
    std::uint8_t ip_ttl{0U};
    std::uint16_t ip_identification{0U};
    bool ip_dont_fragment{false};
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    OSProbeTimePoint received_at{};
    core::IpAddress source_ip{};
    core::IpAddress destination_ip{};
};

enum class OSProbeDisposition : std::uint8_t {
    Matching = 0,
    Unrelated,
    Malformed
};

struct OSProbeAssessment final {
    core::StatusCode status{core::StatusCode::Ok};
    OSProbeDisposition disposition{OSProbeDisposition::Unrelated};
    ResponseBehavior response_behavior{ResponseBehavior::Unknown};
    std::optional<TCPObservation> tcp_observation;
    std::optional<ICMPObservation> icmp_observation;
    std::optional<UDPObservation> udp_observation;
};

class OSProbe {
public:
    virtual ~OSProbe() = default;

    virtual OSProbeType type() const noexcept = 0;
    virtual core::StatusCode build(
        OSProbeId id,
        const core::Host &host,
        const OSProbeConfig &config,
        OSProbeSubmission &submission) const = 0;
    virtual OSProbeAssessment assess(
        const OSProbeResponse &response,
        const OSProbeSubmission &submission) const = 0;
};

std::unique_ptr<OSProbe> make_os_probe(OSProbeType type);

using OSProbeCallback = std::function<void(const OSProbeResponse &)>;

class OSProbeTransport {
public:
    virtual ~OSProbeTransport() = default;

    virtual bool supports(OSProbeType type) const noexcept = 0;
    virtual std::string local_source_address() const { return {}; }
    virtual core::StatusCode submit(OSProbeSubmission submission, OSProbeCallback callback) = 0;
    virtual core::StatusCode cancel(OSProbeId id) noexcept = 0;
};

class RecordingOSProbeTransport final : public OSProbeTransport {
public:
    bool supports(OSProbeType) const noexcept override;
    core::StatusCode submit(OSProbeSubmission submission, OSProbeCallback callback) override;
    core::StatusCode cancel(OSProbeId id) noexcept override;

    void deliver(OSProbeResponse response);
    const std::vector<OSProbeSubmission> &submissions() const noexcept;

private:
    std::vector<OSProbeSubmission> submissions_;
    std::unordered_map<OSProbeId, OSProbeCallback> callbacks_;
};

bool live_os_fingerprinting_available() noexcept;

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_PROBE_HPP
