#ifndef SKAN_OSDETECT_OS_FINGERPRINT_HPP
#define SKAN_OSDETECT_OS_FINGERPRINT_HPP

#include <string>

#include "osdetect/os_types.hpp"
#include "packet/ipv4.hpp"
#include "packet/tcp.hpp"

namespace skan::osdetect {

TCPObservation observe_tcp_response(
    std::string source_address,
    std::string destination_address,
    const packet::IPv4 &ip,
    const packet::TCP &tcp,
    ResponseBehavior response_behavior,
    OSProbeStatus probe_status = OSProbeStatus::ResponseReceived);

ICMPObservation observe_icmp_response(
    const packet::IPv4 &ip,
    std::uint8_t type,
    std::uint8_t code,
    ResponseBehavior response_behavior,
    OSProbeStatus probe_status = OSProbeStatus::ResponseReceived);

void append_observation(ObservedOSFingerprint &fingerprint, TCPObservation observation);
void append_observation(ObservedOSFingerprint &fingerprint, ICMPObservation observation);
void append_observation(ObservedOSFingerprint &fingerprint, UDPObservation observation);

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_FINGERPRINT_HPP
