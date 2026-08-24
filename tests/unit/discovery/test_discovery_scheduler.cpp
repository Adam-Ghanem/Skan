#include <cassert>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "discovery/discovery_scheduler.hpp"
#include "packet/icmp.hpp"
#include "packet/tcp.hpp"

namespace {

skan::core::Host make_host(const std::string &address)
{
    return skan::core::Host{address, std::nullopt, false};
}

skan::discovery::DiscoveryResponse icmp_reply(const skan::discovery::ProbeSubmission &submission)
{
    skan::packet::ICMP reply(skan::packet::IcmpType::EchoReply);
    reply.set_identifier(submission.correlation_identifier);
    reply.set_sequence(submission.correlation_sequence);
    reply.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
    return skan::discovery::DiscoveryResponse{
        submission.id, submission.target, reply.serialize(), skan::discovery::DiscoveryClock::now()};
}

skan::discovery::DiscoveryResponse tcp_rst(const skan::discovery::ProbeSubmission &submission)
{
    skan::packet::TCP response;
    response.set_source_port(submission.port);
    response.set_destination_port(submission.source_port);
    response.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Rst));
    return skan::discovery::DiscoveryResponse{
        submission.id, submission.target, response.serialize(), skan::discovery::DiscoveryClock::now()};
}

} // namespace

int main()
{
    using namespace skan::discovery;

    skan::io::IOEngine io_engine;
    RecordingTransport transport;
    DiscoveryConfig config;
    config.probes = {ProbeType::IcmpEcho, ProbeType::Tcp};
    config.timeout = std::chrono::milliseconds{5};
    config.max_outstanding = 4U;
    DiscoveryScheduler scheduler(io_engine, AuthorizationGate::loopback_only(), config, transport);
    const skan::core::Target target{"local", {make_host("127.0.0.1")}};

    assert(scheduler.submit(target) == skan::core::StatusCode::Ok);
    assert(transport.submissions().size() == 2U);
    assert(scheduler.pending_count() == 2U);
    const ProbeSubmission icmp_submission = transport.submissions()[0];
    const ProbeSubmission tcp_submission = transport.submissions()[1];

    const auto sent = DiscoveryClock::now();
    DiscoveryResponse response = icmp_reply(icmp_submission);
    response.received_at = sent + std::chrono::milliseconds{2};
    assert(scheduler.receive(response) == skan::core::StatusCode::Ok);
    assert(scheduler.host_state("127.0.0.1") == HostState::Up);
    assert(scheduler.pending_count() == 1U);
    assert(scheduler.results().back().responded);
    assert(scheduler.results().back().rtt_ms.has_value());
    assert(*scheduler.results().back().rtt_ms >= 1.0);
    assert(scheduler.receive(response) == skan::core::StatusCode::Ok);
    assert(scheduler.duplicate_response_count() == 1U);
    assert(scheduler.receive(tcp_rst(tcp_submission)) == skan::core::StatusCode::Ok);
    assert(scheduler.complete());
    assert(scheduler.results().back().reason == DiscoveryReason::TcpRst);

    DiscoveryConfig timeout_config;
    timeout_config.probes = {ProbeType::Tcp};
    timeout_config.timeout = std::chrono::milliseconds{1};
    timeout_config.max_outstanding = 2U;
    RecordingTransport timeout_transport;
    skan::io::IOEngine timeout_io;
    DiscoveryScheduler timeout_scheduler(
        timeout_io, AuthorizationGate::loopback_only(), timeout_config, timeout_transport);
    assert(timeout_scheduler.submit(target) == skan::core::StatusCode::Ok);
    const ProbeSubmission timed_out_submission = timeout_transport.submissions().front();
    assert(timeout_scheduler.run_once(50) == skan::core::StatusCode::Ok);
    assert(timeout_scheduler.complete());
    assert(timeout_scheduler.host_state("127.0.0.1") == HostState::Unknown);
    assert(!timeout_scheduler.results().empty());
    assert(timeout_scheduler.results().back().reason == DiscoveryReason::Timeout);
    DiscoveryResponse late = tcp_rst(timed_out_submission);
    assert(timeout_scheduler.receive(late) == skan::core::StatusCode::NotFound);
    assert(timeout_scheduler.late_response_count() == 1U);
    assert(timeout_scheduler.host_state("127.0.0.1") == HostState::Unknown);

    RecordingTransport unauthorized_transport;
    skan::io::IOEngine unauthorized_io;
    DiscoveryScheduler unauthorized_scheduler(
        unauthorized_io,
        AuthorizationGate([](const skan::core::Target &, const skan::core::Host &) { return false; }),
        timeout_config,
        unauthorized_transport);
    assert(unauthorized_scheduler.submit(target) == skan::core::StatusCode::PermissionDenied);
    assert(unauthorized_scheduler.pending_count() == 0U);
    assert(unauthorized_scheduler.results().size() == 1U);
    assert(unauthorized_scheduler.results().front().reason == DiscoveryReason::UnauthorizedTarget);

    RecordingTransport invalid_transport;
    skan::io::IOEngine invalid_io;
    DiscoveryScheduler invalid_scheduler(
        invalid_io, AuthorizationGate::loopback_only(), timeout_config, invalid_transport);
    const skan::core::Target empty_target{"empty", {}};
    assert(invalid_scheduler.submit(empty_target) == skan::core::StatusCode::InvalidArgument);
    const skan::core::Target malformed_target{"malformed", {make_host("127.0.0")}};
    assert(invalid_scheduler.submit(malformed_target) == skan::core::StatusCode::InvalidArgument);
    assert(invalid_scheduler.results().front().reason == DiscoveryReason::InvalidTarget);

    DiscoveryConfig bounded_config;
    bounded_config.probes = {ProbeType::IcmpEcho, ProbeType::Tcp};
    bounded_config.max_outstanding = 1U;
    RecordingTransport bounded_transport;
    skan::io::IOEngine bounded_io;
    DiscoveryScheduler bounded_scheduler(
        bounded_io, AuthorizationGate::loopback_only(), bounded_config, bounded_transport);
    assert(bounded_scheduler.submit(target) == skan::core::StatusCode::IoError);
    assert(bounded_scheduler.pending_count() == 0U);

    DiscoveryConfig malformed_config;
    malformed_config.probes = {ProbeType::IcmpEcho};
    malformed_config.timeout = std::chrono::milliseconds{20};
    RecordingTransport malformed_transport;
    skan::io::IOEngine malformed_io;
    DiscoveryScheduler malformed_scheduler(
        malformed_io, AuthorizationGate::loopback_only(), malformed_config, malformed_transport);
    assert(malformed_scheduler.submit(target) == skan::core::StatusCode::Ok);
    const ProbeSubmission malformed_submission = malformed_transport.submissions().front();
    assert(malformed_scheduler.receive(DiscoveryResponse{
        malformed_submission.id, malformed_submission.target, {0x08U, 0x00U}, DiscoveryClock::now()}) ==
           skan::core::StatusCode::ParseError);
    assert(malformed_scheduler.complete());
    assert(malformed_scheduler.results().back().reason == DiscoveryReason::MalformedResponse);
    assert(malformed_scheduler.receive(DiscoveryResponse{
        malformed_submission.id, malformed_submission.target, {0x08U, 0x00U}, DiscoveryClock::now()}) ==
           skan::core::StatusCode::Ok);
    assert(malformed_scheduler.duplicate_response_count() == 1U);

    DiscoveryConfig multi_config;
    multi_config.probes = {ProbeType::IcmpEcho};
    multi_config.timeout = std::chrono::milliseconds{2};
    multi_config.max_outstanding = 4U;
    RecordingTransport multi_transport;
    skan::io::IOEngine multi_io;
    DiscoveryScheduler multi_scheduler(
        multi_io, AuthorizationGate::loopback_only(), multi_config, multi_transport);
    const skan::core::Target multiple_targets{
        "loopback-pair", {make_host("127.0.0.1"), make_host("127.0.0.2")}};
    assert(multi_scheduler.submit(multiple_targets) == skan::core::StatusCode::Ok);
    assert(multi_transport.submissions().size() == 2U);
    assert(multi_scheduler.receive(icmp_reply(multi_transport.submissions().front())) ==
           skan::core::StatusCode::Ok);
    assert(multi_scheduler.host_state("127.0.0.1") == HostState::Up);
    assert(multi_scheduler.run_once(30) == skan::core::StatusCode::Ok);
    assert(multi_scheduler.complete());
    assert(multi_scheduler.host_state("127.0.0.2") == HostState::Unknown);
    return 0;
}
