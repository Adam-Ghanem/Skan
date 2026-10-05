#include <cassert>
#include <cerrno>
#include <chrono>
#include <string>

#include "detect/service_scheduler.hpp"

namespace {

using namespace skan;
using namespace std::string_literals;

portscan::PortResult endpoint()
{
    portscan::PortResult port;
    port.target = "127.0.0.1";
    port.port = {443U, portscan::Protocol::Tcp};
    port.state = portscan::PortState::Open;
    return port;
}

detect::ServiceResponse event(const detect::ServiceSubmission &submission, detect::ServiceResponseKind kind,
    std::string_view bytes = {})
{
    detect::ServiceResponse response;
    response.id = submission.id;
    response.source_address = submission.target;
    response.kind = kind;
    response.bytes.assign(bytes.begin(), bytes.end());
    response.received_at = detect::DetectionClock::now();
    return response;
}

void established(detect::RecordingServiceTransport &transport, const detect::ServiceSubmission &submission,
    const char *version = "TLS 1.3")
{
    auto response = event(submission, detect::ServiceResponseKind::TlsEstablished);
    response.tls.emplace();
    response.tls->detected = true;
    response.tls->protocol_version = version;
    response.tls->certificate_subject = "CN=CertificateProduct/9.9.9";
    response.tls->alpn = {"http/1.1"};
    transport.deliver(response);
}

void tls_events_require_attribution_and_handshake_before_application()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    io::IOEngine engine;
    detect::RecordingServiceTransport transport;
    detect::ServiceDetectionConfig configuration;
    configuration.max_probes_per_port = 2U;
    detect::ServiceScheduler scheduler(engine, transport, database, configuration);
    assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
    const auto hello = transport.submissions().front();
    assert(hello.tls_session && hello.tls_handshake_only && hello.payload.empty());
    transport.deliver(event(hello, detect::ServiceResponseKind::Data,
        "HTTP/1.1 200 OK\r\nServer: Fake/9.9.9\r\n\r\n"));
    assert(!scheduler.complete() && scheduler.results().empty());
    auto invalid = event(hello, detect::ServiceResponseKind::TlsEstablished);
    invalid.tls.emplace();
    invalid.tls->detected = true;
    invalid.tls->protocol_version = "TLS 1.3";
    invalid.source_address = "127.0.0.2";
    transport.deliver(invalid);
    assert(transport.submissions().size() == 1U);
    established(transport, hello, "TLS 1.2");
    assert(transport.submissions().size() == 2U);
    const auto application = transport.submissions().back();
    assert(application.tls_session && !application.tls_handshake_only);
    // A late response for the cancelled ClientHello cannot affect the fallback.
    transport.deliver(event(hello, detect::ServiceResponseKind::TlsError));
    assert(scheduler.results().empty());
    established(transport, application);
    transport.deliver(event(application, detect::ServiceResponseKind::Data,
        "HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nContent-Length: 0\r\n\r\n"));
    transport.deliver(event(application, detect::ServiceResponseKind::Closed));
    assert(scheduler.complete());
    const auto &result = scheduler.results().front();
    assert(result.service == "https" && result.product == "nginx" && result.version == "1.26.2");
    assert(result.tls_version == "TLS 1.3" && result.tunnel == "tls");
}

void failed_handshake_has_an_explicit_error_and_no_tls_identity()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    io::IOEngine engine;
    detect::RecordingServiceTransport transport;
    detect::ServiceDetectionConfig configuration;
    configuration.max_probes_per_port = 1U;
    detect::ServiceScheduler scheduler(engine, transport, database, configuration);
    assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
    transport.deliver(event(transport.submissions().front(), detect::ServiceResponseKind::TlsError));
    assert(scheduler.complete());
    const auto &result = scheduler.results().front();
    assert(result.state == detect::DetectionState::Unknown && result.service.empty() && !result.tls_detected);
    assert(std::string{detect::detection_error_name(result.error)} == "TLS_FAILURE");
}

void failed_handshake_can_recover_plaintext_without_fabricating_a_tunnel()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    io::IOEngine engine;
    detect::RecordingServiceTransport transport;
    detect::ServiceDetectionConfig configuration;
    configuration.max_probes_per_port = 2U;
    detect::ServiceScheduler scheduler(engine, transport, database, configuration);
    assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
    transport.deliver(event(transport.submissions().front(), detect::ServiceResponseKind::TlsError));
    const auto plaintext = transport.submissions().back();
    assert(!plaintext.tls_session);
    transport.deliver(event(plaintext, detect::ServiceResponseKind::Data,
        "HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nContent-Length: 0\r\n\r\n"));
    transport.deliver(event(plaintext, detect::ServiceResponseKind::Closed));
    const auto &result = scheduler.results().front();
    assert(result.service == "http" && result.tunnel.empty() && !result.tls_detected);
}

void failed_current_tls_application_does_not_publish_provisional_identity()
{
    for (auto kind : {detect::ServiceResponseKind::TlsError, detect::ServiceResponseKind::SocketError}) {
        const auto database = detect::ServiceProbeDatabase::built_in();
        io::IOEngine engine;
        detect::RecordingServiceTransport transport;
        detect::ServiceDetectionConfig configuration;
        configuration.max_probes_per_port = 2U;
        detect::ServiceScheduler scheduler(engine, transport, database, configuration);
        assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
        established(transport, transport.submissions().front());
        const auto application = transport.submissions().back();
        established(transport, application);
        transport.deliver(event(application, detect::ServiceResponseKind::Data,
            "HTTP/1.1 200 OK\r\nServer: Unfinished/9.9.9\r\n\r\nbody"));
        // Duplicate handshake acknowledgement must not snapshot provisional HTTP.
        established(transport, application);
        auto failure = event(application, kind);
        failure.system_error = ECONNRESET;
        transport.deliver(failure);
        assert(scheduler.complete());
        const auto &result = scheduler.results().front();
        assert(result.service == "tls" && result.tls_detected);
        assert(result.product.empty() && result.version.empty());
    }
}

void oversized_application_retains_only_transport_evidence()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    io::IOEngine engine;
    detect::RecordingServiceTransport transport;
    detect::ServiceDetectionConfig configuration;
    configuration.max_probes_per_port = 2U;
    configuration.max_response_bytes = 32U;
    detect::ServiceScheduler scheduler(engine, transport, database, configuration);
    assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
    established(transport, transport.submissions().front());
    const auto application = transport.submissions().back();
    established(transport, application);
    transport.deliver(event(application, detect::ServiceResponseKind::Data, std::string(33U, 'x')));
    assert(scheduler.complete());
    const auto &result = scheduler.results().front();
    assert(result.state == detect::DetectionState::ResponseTooLarge);
    assert(result.service == "tls" && result.tls_detected && result.tunnel == "tls");
    assert(result.product.empty() && result.version.empty());
}

void explicit_server_names_reach_tls_fallbacks_and_default_http_host()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    for (const std::string &name : std::vector<std::string>{"fixture.test", "A-1.example.test", std::string(63U, 'a') + ".test"}) {
        io::IOEngine engine;
        detect::RecordingServiceTransport transport;
        detect::ServiceDetectionConfig configuration;
        configuration.tls_server_name = name;
        configuration.max_probes_per_port = 2U;
        detect::ServiceScheduler scheduler(engine, transport, database, configuration);
        assert(scheduler.submit({endpoint()}) == core::StatusCode::Ok);
        assert(transport.submissions().front().server_name == name);
        established(transport, transport.submissions().front());
        const auto &application = transport.submissions().back();
        assert(application.tls_session && application.server_name == name);
        assert(application.payload.find("\r\nHost: " + name + "\r\n") != std::string::npos);
    }
}

void invalid_server_names_are_rejected_before_a_submission()
{
    const auto database = detect::ServiceProbeDatabase::built_in();
    for (const std::string &name : std::vector<std::string>{"bad\r\nHost: fake", "-bad.test", "bad-.test",
         "a..test", ".test", "test.", "bad_name.test", "127.0.0.1", "::1", "bad\0.test"s,
         std::string(64U, 'x') + ".test", std::string(254U, 'x'), "non\xc3\xa9.test"}) {
        io::IOEngine engine;
        detect::RecordingServiceTransport transport;
        detect::ServiceDetectionConfig configuration;
        configuration.tls_server_name = name;
        detect::ServiceScheduler scheduler(engine, transport, database, configuration);
        assert(scheduler.submit({endpoint()}) == core::StatusCode::InvalidArgument);
        assert(transport.submissions().empty());
    }
}

} // namespace

int main()
{
    explicit_server_names_reach_tls_fallbacks_and_default_http_host();
    invalid_server_names_are_rejected_before_a_submission();
    tls_events_require_attribution_and_handshake_before_application();
    failed_handshake_can_recover_plaintext_without_fabricating_a_tunnel();
    failed_handshake_has_an_explicit_error_and_no_tls_identity();
    failed_current_tls_application_does_not_publish_provisional_identity();
    oversized_application_retains_only_transport_evidence();
}
