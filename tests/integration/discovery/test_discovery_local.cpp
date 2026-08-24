#include <cassert>
#include <chrono>
#include <cstdint>

#include "discovery/discovery.hpp"
#include "packet/icmp.hpp"

int main()
{
    using namespace skan::discovery;

    skan::io::IOEngine io_engine;
    RecordingTransport transport;
    DiscoveryConfig config;
    config.probes = {ProbeType::IcmpEcho};
    config.timeout = std::chrono::milliseconds{10};
    config.max_outstanding = 4U;
    Discovery discovery(io_engine, config, transport);
    const skan::core::Target target{"localhost", {skan::core::Host{"127.0.0.1", std::nullopt, false}}};

    assert(discovery.submit(target) == skan::core::StatusCode::Ok);
    assert(discovery.pending_count() == 1U);
    assert(transport.submissions().size() == 1U);
    const ProbeSubmission &submission = transport.submissions().front();

    skan::packet::ICMP reply(skan::packet::IcmpType::EchoReply);
    reply.set_identifier(submission.correlation_identifier);
    reply.set_sequence(submission.correlation_sequence);
    reply.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
    assert(discovery.receive(DiscoveryResponse{
        submission.id,
        "127.0.0.1",
        reply.serialize(),
        DiscoveryClock::now() + std::chrono::milliseconds{1}}) == skan::core::StatusCode::Ok);
    assert(discovery.run_once(0) == skan::core::StatusCode::Ok);
    assert(discovery.complete());
    assert(discovery.host_state("127.0.0.1") == HostState::Up);
    assert(discovery.results().size() == 1U);

    skan::io::IOEngine timeout_io;
    RecordingTransport timeout_transport;
    DiscoveryConfig timeout_config = config;
    timeout_config.timeout = std::chrono::milliseconds{1};
    Discovery timeout_discovery(
        timeout_io, timeout_config, timeout_transport);
    assert(timeout_discovery.submit(target) == skan::core::StatusCode::Ok);
    assert(timeout_discovery.run_once(50) == skan::core::StatusCode::Ok);
    assert(timeout_discovery.complete());
    assert(timeout_discovery.host_state("127.0.0.1") == HostState::Unknown);
    return 0;
}
