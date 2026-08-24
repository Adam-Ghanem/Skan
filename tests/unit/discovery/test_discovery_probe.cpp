#include <cassert>
#include <cstdint>
#include <vector>
#include <utility>

#include "discovery/arp_discovery.hpp"
#include "discovery/icmp_discovery.hpp"
#include "discovery/tcp_discovery.hpp"
#include "packet/icmp.hpp"
#include "packet/tcp.hpp"

namespace {

skan::core::Host host(std::string address)
{
    return skan::core::Host{std::move(address), std::nullopt, false};
}

} // namespace

int main()
{
    using namespace skan::discovery;

    const skan::core::Target local_target{"local", {host("127.0.0.1")}};
    DiscoveryConfig config;
    IcmpDiscoveryProbe icmp_probe;
    ProbeSubmission icmp_submission;
    assert(icmp_probe.build(1U, local_target.resolved_hosts.front(), config, icmp_submission) == skan::core::StatusCode::Ok);
    assert(icmp_submission.type == ProbeType::IcmpEcho);
    assert(!icmp_submission.packet.empty());

    skan::packet::ICMP echo_reply(skan::packet::IcmpType::EchoReply);
    echo_reply.set_identifier(icmp_submission.correlation_identifier);
    echo_reply.set_sequence(icmp_submission.correlation_sequence);
    echo_reply.set_payload({0x53U, 0x4BU, 0x41U, 0x4EU});
    DiscoveryResponse icmp_response{1U, "127.0.0.1", echo_reply.serialize(), DiscoveryClock::now()};
    assert(icmp_probe.assess(icmp_response, icmp_submission) == ResponseDisposition::Matching);
    assert(icmp_probe.positive_reason(icmp_response) == DiscoveryReason::IcmpEchoReply);
    skan::packet::ICMP wrong_sequence = echo_reply;
    wrong_sequence.set_sequence(static_cast<std::uint16_t>(icmp_submission.correlation_sequence + 1U));
    icmp_response.bytes = wrong_sequence.serialize();
    assert(icmp_probe.assess(icmp_response, icmp_submission) == ResponseDisposition::Unrelated);
    icmp_response.bytes = {0x08U, 0x00U};
    assert(icmp_probe.assess(icmp_response, icmp_submission) == ResponseDisposition::Malformed);
    icmp_response.bytes = echo_reply.serialize();
    icmp_response.source_address = "127.0.0.2";
    assert(icmp_probe.assess(icmp_response, icmp_submission) == ResponseDisposition::Unrelated);
    assert(icmp_probe.build(0U, local_target.resolved_hosts.front(), config, icmp_submission) == skan::core::StatusCode::InvalidArgument);

    TcpDiscoveryProbe tcp_probe;
    config.tcp_port = 8080U;
    ProbeSubmission tcp_submission;
    assert(tcp_probe.build(2U, local_target.resolved_hosts.front(), config, tcp_submission) == skan::core::StatusCode::Ok);
    skan::packet::TCP syn_ack;
    syn_ack.set_source_port(config.tcp_port);
    syn_ack.set_destination_port(tcp_submission.source_port);
    syn_ack.set_sequence_number(0x100U);
    syn_ack.set_acknowledgment_number(tcp_submission.sequence_number + 1U);
    syn_ack.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Syn) |
                      static_cast<std::uint16_t>(skan::packet::TcpFlag::Ack));
    syn_ack.set_window(4096U);
    DiscoveryResponse tcp_response{2U, "127.0.0.1", syn_ack.serialize(), DiscoveryClock::now()};
    assert(tcp_probe.assess(tcp_response, tcp_submission) == ResponseDisposition::Matching);
    assert(tcp_probe.positive_reason(tcp_response) == DiscoveryReason::TcpSynAck);

    skan::packet::TCP rst = syn_ack;
    rst.set_flags(static_cast<std::uint16_t>(skan::packet::TcpFlag::Rst));
    tcp_response.bytes = rst.serialize();
    assert(tcp_probe.assess(tcp_response, tcp_submission) == ResponseDisposition::Matching);
    assert(tcp_probe.positive_reason(tcp_response) == DiscoveryReason::TcpRst);
    tcp_response.bytes = {0U};
    assert(tcp_probe.assess(tcp_response, tcp_submission) == ResponseDisposition::Malformed);
    tcp_response.bytes = syn_ack.serialize();
    tcp_response.source_address = "192.0.2.1";
    assert(tcp_probe.assess(tcp_response, tcp_submission) == ResponseDisposition::Unrelated);

    ArpDiscoveryProbe arp_probe;
    const skan::core::Target arp_target{"lab", {host("192.0.2.5")}};
    ProbeSubmission arp_submission;
    assert(arp_probe.build(3U, arp_target.resolved_hosts.front(), config, arp_submission) == skan::core::StatusCode::Ok);
    const auto request = ArpMessage::parse(arp_submission.packet);
    assert(request.has_value());
    assert(request->operation == 1U);
    assert(request->target_ipv4 == 0xC0000205U);
    ArpMessage reply;
    reply.operation = 2U;
    reply.sender_mac = {0x02U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU};
    reply.sender_ipv4 = arp_submission.target_ipv4;
    reply.target_mac = request->sender_mac;
    reply.target_ipv4 = arp_submission.source_ipv4;
    DiscoveryResponse arp_response{3U, "192.0.2.5", reply.serialize(), DiscoveryClock::now()};
    assert(arp_probe.assess(arp_response, arp_submission) == ResponseDisposition::Matching);
    assert(arp_probe.positive_reason(arp_response) == DiscoveryReason::ArpReply);
    arp_response.bytes.resize(27U);
    assert(arp_probe.assess(arp_response, arp_submission) == ResponseDisposition::Malformed);
    return 0;
}
