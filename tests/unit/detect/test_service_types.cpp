#include <cassert>
#include <chrono>
#include <string>

#include "detect/service_types.hpp"

int main()
{
    using namespace skan::detect;
    ServiceResult result;
    result.target = "127.0.0.1";
    result.port = {80U, skan::portscan::Protocol::Tcp};
    result.protocol = skan::portscan::Protocol::Tcp;
    result.port_state = skan::portscan::PortState::Open;
    result.state = DetectionState::Detected;
    result.service = "http";
    result.product = "HTTP";
    result.version = "1.0";
    result.confidence = 0.8;
    result.method = DetectionMethod::Probe;
    result.probe_name = "HTTPGet";
    result.rtt_ms = 1.5;
    assert(result.port.number == 80U);
    assert(result.port_state == skan::portscan::PortState::Open);
    assert(result.protocol == skan::portscan::Protocol::Tcp);
    assert(result.rtt_ms.value() == 1.5);

    ServiceResult other = result;
    other.port.number = 22U;
    assert(service_result_less(other, result));
    assert(!service_result_less(result, other));
    assert(std::string{detection_state_name(DetectionState::Detected)} == "DETECTED");
    assert(std::string{detection_error_name(DetectionError::ResponseTooLarge)} == "RESPONSE_TOO_LARGE");
    assert(std::string{detection_method_name(DetectionMethod::Banner)} == "banner");
    return 0;
}
