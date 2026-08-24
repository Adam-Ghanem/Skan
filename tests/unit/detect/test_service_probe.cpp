#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#include "detect/service_probe.hpp"

int main()
{
    using namespace skan::detect;
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::parse(
        "Probe TCP Demo rarity=1 ports=80\n"
        "send \"PING\\r\\n\"\n"
        "match type=prefix pattern=\"PONG\" service=demo product=Demo confidence=0.8\n",
        status);
    assert(status == skan::core::StatusCode::Ok);
    ServiceProbe probe(database.probes().front(), 4U);
    ServiceSubmission submission;
    const skan::core::Host host{"127.0.0.1", std::nullopt, true};
    assert(probe.build(42U, host, {80U, skan::portscan::Protocol::Tcp}, submission) == skan::core::StatusCode::Ok);
    assert(submission.id == 42U);
    assert(submission.payload == "PING\r\n");
    assert(submission.max_response_bytes == 4U);

    std::string bounded;
    DetectionError error = DetectionError::InternalError;
    ServiceResponse data{42U, "127.0.0.1", ServiceResponseKind::Data, 0,
                         {'P', 'O', 'N', 'G'}, false, DetectionClock::now()};
    assert(probe.assess(data, submission, bounded, error) == skan::core::StatusCode::Ok);
    assert(bounded == "PONG");
    assert(error == DetectionError::None);

    ServiceResponse too_large{42U, "127.0.0.1", ServiceResponseKind::Data, 0,
                              {'P', 'O', 'N', 'G', '!'}, false, DetectionClock::now()};
    assert(probe.assess(too_large, submission, bounded, error) == skan::core::StatusCode::MemoryError);
    assert(error == DetectionError::ResponseTooLarge);

    ServiceResponse wrong_source{42U, "127.0.0.2", ServiceResponseKind::Data, 0, {}, false,
                                 DetectionClock::now()};
    assert(probe.assess(wrong_source, submission, bounded, error) == skan::core::StatusCode::NotFound);
    ServiceResponse closed{42U, "127.0.0.1", ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()};
    assert(probe.assess(closed, submission, bounded, error) == skan::core::StatusCode::NotFound);
    assert(error == DetectionError::ConnectionClosed);

    RecordingServiceTransport recording;
    bool delivered = false;
    assert(recording.submit(submission, [&delivered](const ServiceResponse &) { delivered = true; }) ==
           skan::core::StatusCode::Ok);
    recording.deliver(data);
    assert(delivered);
    recording.deliver(data);
    assert(recording.cancel(submission.id) == skan::core::StatusCode::Ok);
    return 0;
}
