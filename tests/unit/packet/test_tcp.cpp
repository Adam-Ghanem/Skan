#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "packet/checksum.hpp"
#include "packet/tcp.hpp"

int main()
{
    using skan::packet::TCP;
    using skan::packet::TcpFlag;
    using skan::packet::TcpOption;
    using skan::packet::TcpOptionKind;

    TCP tcp;
    tcp.set_source_port(12345U);
    tcp.set_destination_port(443U);
    tcp.set_sequence_number(0x01020304U);
    tcp.set_acknowledgment_number(0x05060708U);
    tcp.set_flags(static_cast<std::uint16_t>(TcpFlag::Syn) | static_cast<std::uint16_t>(TcpFlag::Ack));
    tcp.set_window(0x7210U);
    tcp.set_options({
        TcpOption{TcpOptionKind::Mss, 1460U, 0U, 0U},
        TcpOption{TcpOptionKind::WindowScale, 7U, 0U, 0U},
        TcpOption{TcpOptionKind::SackPermitted, 0U, 0U, 0U},
        TcpOption{TcpOptionKind::Timestamp, 0U, 0x11223344U, 0x55667788U}});
    tcp.set_payload({0xDEU, 0xADU, 0xBEU, 0xEFU});

    assert(tcp.validate());
    assert(tcp.data_offset() == 10U);
    assert(tcp.serialized_size() == 44U);
    assert(tcp.options().size() == 4U);
    assert(tcp.payload().size() == 4U);
    assert(skan::packet::has_flag(tcp.flags(), TcpFlag::Syn));
    assert(skan::packet::has_flag(tcp.flags(), TcpFlag::Ack));
    assert(!skan::packet::has_flag(tcp.flags(), TcpFlag::Rst));

    const std::uint32_t source = 0xC0000201U;
    const std::uint32_t destination = 0xC6336402U;
    std::vector<std::uint8_t> bytes(tcp.serialized_size(), 0U);
    assert(tcp.serialize_with_checksum(std::span<std::uint8_t>{bytes}, source, destination) == skan::core::StatusCode::Ok);
    assert(tcp.checksum_for_ipv4(source, destination) != 0U);
    assert(skan::packet::checksum::ipv4_pseudo_header(source, destination, 6U,
        std::span<const std::uint8_t>{bytes}) == 0U);

    const auto parsed = TCP::parse(std::span<const std::uint8_t>{bytes});
    assert(parsed.has_value());
    assert(parsed->source_port() == 12345U);
    assert(parsed->destination_port() == 443U);
    assert(parsed->sequence_number() == 0x01020304U);
    assert(parsed->acknowledgment_number() == 0x05060708U);
    assert(parsed->data_offset() == 10U);
    assert(parsed->window() == 0x7210U);
    assert(parsed->options().size() == 4U);
    assert(parsed->payload() == tcp.payload());
    assert(!TCP::parse(std::span<const std::uint8_t>{bytes.data(), 19U}).has_value());

    std::array<std::uint8_t, 24U> unknown_option{};
    std::copy(bytes.begin(), bytes.begin() + 24, unknown_option.begin());
    unknown_option[12] = 0x60U;
    unknown_option[20] = 30U;
    unknown_option[21] = 4U;
    unknown_option[22] = 0xAAU;
    unknown_option[23] = 0x55U;
    const auto parsed_unknown = TCP::parse(std::span<const std::uint8_t>{unknown_option});
    assert(parsed_unknown.has_value());
    assert(parsed_unknown->options().empty());
    auto malformed_option = unknown_option;
    malformed_option[21] = 1U;
    assert(!TCP::parse(std::span<const std::uint8_t>{malformed_option}).has_value());

    TCP syn;
    syn.set_source_port(12345U);
    syn.set_destination_port(80U);
    syn.set_sequence_number(0x11223344U);
    syn.set_flags(static_cast<std::uint16_t>(TcpFlag::Syn));
    syn.set_window(0xFAF0U);
    assert(syn.serialized_size() == TCP::kMinimumHeaderSize);
    const std::vector<std::uint8_t> syn_bytes = syn.serialize();
    const std::array<std::uint8_t, 20U> expected_syn{
        0x30U, 0x39U, 0x00U, 0x50U, 0x11U, 0x22U, 0x33U, 0x44U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x50U, 0x02U, 0xFAU, 0xF0U,
        0x00U, 0x00U, 0x00U, 0x00U};
    assert(std::equal(syn_bytes.begin(), syn_bytes.end(), expected_syn.begin()));
    std::array<std::uint8_t, 20U> checksummed_syn{};
    assert(syn.serialize_with_checksum(std::span<std::uint8_t>{checksummed_syn}, source, destination) == skan::core::StatusCode::Ok);
    const std::array<std::uint8_t, 20U> expected_checksummed_syn{
        0x30U, 0x39U, 0x00U, 0x50U, 0x11U, 0x22U, 0x33U, 0x44U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x50U, 0x02U, 0xFAU, 0xF0U,
        0x53U, 0xCBU, 0x00U, 0x00U};
    assert(std::equal(checksummed_syn.begin(), checksummed_syn.end(), expected_checksummed_syn.begin()));

    TCP invalid;
    invalid.set_options(std::vector<TcpOption>(20U, TcpOption{TcpOptionKind::Mss, 1U, 0U, 0U}));
    assert(!invalid.validate());
    std::array<std::uint8_t, 20U> invalid_offset{};
    invalid_offset[12] = 0x40U;
    assert(!TCP::parse(std::span<const std::uint8_t>{invalid_offset}).has_value());
    return 0;
}
