#include <cassert>
#include <algorithm>
#include <iostream>

#include "io/io_engine.hpp"
#include "net/interface.hpp"
#include "net/network_scan_transport.hpp"

namespace {

void test_tcp_reply_correlation()
{
    using namespace skan;
    for (const bool ipv6 : {false, true}) {
        portscan::PortSubmission submission;
        submission.probe = portscan::ScanProbeType::TcpAck;
        submission.source_ip = *core::parse_ip_address(ipv6 ? "2001:db8::1" : "192.0.2.1");
        submission.target_ip = *core::parse_ip_address(ipv6 ? "2001:db8::2" : "192.0.2.2");
        submission.source_port = 40009U;
        submission.port = {80U, portscan::Protocol::Tcp};
        submission.sequence_number = 123U;
        submission.acknowledgment_number = 456U;
        net::PacketObservation reply;
        reply.status = net::ParseStatus::Valid;
        if (ipv6) {
            reply.ipv6.emplace();
            reply.ipv6->set_next_header(6U);
            reply.ipv6->set_source_address(submission.target_ip.bytes);
            reply.ipv6->set_destination_address(submission.source_ip.bytes);
        } else {
            reply.ipv4.emplace();
            reply.ipv4->set_protocol(6U);
            reply.ipv4->set_source_address(0xc0000202U);
            reply.ipv4->set_destination_address(0xc0000201U);
        }
        reply.tcp.emplace();
        reply.tcp->set_source_port(80U);
        reply.tcp->set_destination_port(40009U);
        reply.tcp->set_sequence_number(456U);
        reply.tcp->set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Rst));
        assert(net::matches_tcp_reply(submission, reply));
        // RFC 9293: without ACK set, the acknowledgment field is not significant.
        reply.tcp->set_acknowledgment_number(999U);
        assert(net::matches_tcp_reply(submission, reply));

        auto invalid = reply;
        invalid.status = net::ParseStatus::MalformedTCP;
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        invalid.tcp.reset();
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        invalid.tcp->set_sequence_number(457U);
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        invalid.tcp->set_source_port(81U);
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        invalid.tcp->set_destination_port(40010U);
        assert(!net::matches_tcp_reply(submission, invalid));
        for (const auto flag : {packet::TcpFlag::Ack, packet::TcpFlag::Syn, packet::TcpFlag::Fin}) {
            invalid = reply;
            invalid.tcp->set_flags(packet::TcpFlag::Rst | flag);
            assert(!net::matches_tcp_reply(submission, invalid));
        }
        invalid = reply;
        invalid.tcp->set_flags(packet::TcpFlag::Syn | packet::TcpFlag::Ack);
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        if (ipv6) {
            invalid.ipv6->set_destination_address(submission.target_ip.bytes);
        } else {
            invalid.ipv4->set_destination_address(0xc0000203U);
        }
        assert(!net::matches_tcp_reply(submission, invalid));
        invalid = reply;
        if (ipv6) {
            invalid.ipv6->set_source_address(submission.source_ip.bytes);
        } else {
            invalid.ipv4->set_source_address(0xc0000203U);
        }
        assert(!net::matches_tcp_reply(submission, invalid));
        auto wrong_family = submission;
        wrong_family.target_ip = *core::parse_ip_address(ipv6 ? "192.0.2.2" : "2001:db8::2");
        assert(!net::matches_tcp_reply(wrong_family, reply));

        // Preserve existing bare RST and correlated SYN/ACK behavior.
        submission.probe = portscan::ScanProbeType::TcpSyn;
        reply.tcp->set_acknowledgment_number(0U);
        assert(net::matches_tcp_reply(submission, reply));
        reply.tcp->set_flags(packet::TcpFlag::Syn | packet::TcpFlag::Ack);
        reply.tcp->set_acknowledgment_number(124U);
        assert(net::matches_tcp_reply(submission, reply));
        reply.tcp->set_acknowledgment_number(125U);
        assert(!net::matches_tcp_reply(submission, reply));
        reply.tcp->set_acknowledgment_number(124U);
        reply.tcp->set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Ack));
        assert(!net::matches_tcp_reply(submission, reply));
        submission.probe = portscan::ScanProbeType::TcpConnect;
        assert(!net::matches_tcp_reply(submission, reply));
    }
}

void test_icmp_quote_correlation()
{
    using namespace skan;
    for (const bool ipv6 : {false, true}) {
        portscan::PortSubmission submission;
        submission.probe = portscan::ScanProbeType::TcpAck;
        submission.source_ip = *core::parse_ip_address(ipv6 ? "2001:db8::1" : "192.0.2.1");
        submission.target_ip = *core::parse_ip_address(ipv6 ? "2001:db8::2" : "192.0.2.2");
        packet::TCP tcp;
        tcp.set_source_port(40009U);
        tcp.set_destination_port(80U);
        tcp.set_sequence_number(123U);
        tcp.set_acknowledgment_number(456U);
        tcp.set_flags(static_cast<std::uint16_t>(packet::TcpFlag::Ack));
        submission.packet.resize(tcp.serialized_size());
        assert(tcp.serialize(submission.packet) == core::StatusCode::Ok);
        const std::size_t header_size = ipv6 ? 40U : 20U;
        std::vector<std::uint8_t> quote(header_size + submission.packet.size());
        net::PacketObservation error;
        error.status = net::ParseStatus::Valid;
        if (ipv6) {
            packet::IPv6 original;
            original.set_next_header(6U);
            original.set_payload_length(20U);
            original.set_source_address(submission.source_ip.bytes);
            original.set_destination_address(submission.target_ip.bytes);
            assert(original.serialize(quote) == core::StatusCode::Ok);
            error.ipv6.emplace();
            error.ipv6->set_destination_address(submission.source_ip.bytes);
            error.icmpv6.emplace(packet::Icmpv6Type::DestinationUnreachable);
        } else {
            packet::IPv4 original;
            original.set_protocol(6U);
            original.set_total_length(40U);
            original.set_source_address(0xc0000201U);
            original.set_destination_address(0xc0000202U);
            assert(original.serialize(quote) == core::StatusCode::Ok);
            error.ipv4.emplace();
            error.ipv4->set_destination_address(0xc0000201U);
            error.icmp.emplace(packet::IcmpType::DestinationUnreachable);
        }
        std::copy(submission.packet.begin(), submission.packet.end(), quote.begin() + header_size);
        const auto set_quote = [ipv6](net::PacketObservation &observation, std::vector<std::uint8_t> bytes) {
            if (ipv6) { observation.icmpv6->set_payload(std::move(bytes)); }
            else { observation.icmp->set_payload(std::move(bytes)); }
        };
        // Routers can originate the outer packet: only the destination is our endpoint.
        for (std::size_t length = 8U; length <= 20U; ++length) {
            auto truncated = quote;
            truncated.resize(header_size + length);
            set_quote(error, truncated);
            assert(net::matches_tcp_unreachable(submission, error));
        }
        set_quote(error, quote);
        auto invalid = error;
        if (ipv6) { invalid.ipv6->set_destination_address(submission.target_ip.bytes); }
        else { invalid.ipv4->set_destination_address(0xc0000203U); }
        assert(!net::matches_tcp_unreachable(submission, invalid));
        invalid = error;
        invalid.status = net::ParseStatus::MalformedICMP;
        assert(!net::matches_tcp_unreachable(submission, invalid));
        invalid = error;
        if (ipv6) { invalid.icmpv6->set_code(255U); }
        else { invalid.icmp->set_code(255U); }
        assert(!net::matches_tcp_unreachable(submission, invalid));
        auto truncated = quote;
        truncated.resize(header_size + 7U);
        set_quote(invalid = error, truncated);
        assert(!net::matches_tcp_unreachable(submission, invalid));
        // Both ports, sequence, ACK identity, and flags must agree when quoted.
        for (const std::size_t offset : {0U, 2U, 4U, 8U, 13U}) {
            auto changed = quote;
            changed[header_size + offset] ^= 1U;
            set_quote(invalid = error, changed);
            assert(!net::matches_tcp_unreachable(submission, invalid));
        }
        auto wrong_endpoint = submission;
        wrong_endpoint.target_ip.bytes[0] ^= 1U;
        assert(!net::matches_tcp_unreachable(wrong_endpoint, error));
        wrong_endpoint = submission;
        wrong_endpoint.source_ip.bytes[0] ^= 1U;
        assert(!net::matches_tcp_unreachable(wrong_endpoint, error));
        auto changed = quote;
        changed[0] = 0U;
        set_quote(invalid = error, changed);
        assert(!net::matches_tcp_unreachable(submission, invalid));
        if (!ipv6) {
            changed = quote;
            changed[10] ^= 1U; // Invalid quoted IPv4 checksum.
            set_quote(invalid = error, changed);
            assert(!net::matches_tcp_unreachable(submission, invalid));
        }
    }
}

} // namespace

int main()
{
    test_tcp_reply_correlation();
    test_icmp_quote_correlation();
    skan::io::IOEngine io_engine;
    assert(io_engine.initialization_status() == skan::core::StatusCode::Ok);

    skan::net::LinuxNetworkScanTransport invalid(
        io_engine, skan::net::NetworkScanConfig{});
    assert(!invalid.supports(skan::portscan::ScanProbeType::TcpSyn));
    assert(invalid.open().status == skan::net::NetworkScanStatus::InvalidConfiguration);

    if (!skan::net::find_interface("lo").has_value()) {
        std::cout << "SKIPPED: loopback interface unavailable\n";
        return 0;
    }
    skan::net::LinuxNetworkScanTransport transport(
        io_engine, skan::net::NetworkScanConfig{"lo", 65535U, true, std::nullopt});
    const skan::net::NetworkScanResult opened = transport.open();
    if (!opened.success()) {
        assert(opened.category != skan::net::PreflightCategory::Ready);
        assert(opened.family == skan::core::AddressFamily::IPv4 || opened.family == skan::core::AddressFamily::IPv6);
        assert(!opened.message.empty());
        std::cout << "SKIPPED: Linux network scan transport unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    assert(transport.supports(skan::portscan::ScanProbeType::TcpSyn));
    assert(transport.supports(skan::portscan::ScanProbeType::TcpAck));
    assert(transport.session().active);
    assert(transport.session().id != 0U);
    assert(transport.capture_file_descriptor() >= 0);
    assert(transport.transport_file_descriptor() >= 0);
    transport.close();
    transport.close();
    assert(!transport.is_open());
    assert(!transport.supports(skan::portscan::ScanProbeType::TcpSyn));
    assert(!transport.supports(skan::portscan::ScanProbeType::TcpAck));
    return 0;
}
