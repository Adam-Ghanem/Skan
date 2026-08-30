#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "detect/tls_metadata.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;

void append(Bytes &target, const Bytes &source)
{
    target.insert(target.end(), source.begin(), source.end());
}

Bytes bytes(std::initializer_list<std::uint8_t> values) { return Bytes{values}; }

Bytes text(std::string_view value)
{
    return Bytes{value.begin(), value.end()};
}

Bytes tlv(std::uint8_t tag, const Bytes &value)
{
    assert(value.size() < 65536U);
    Bytes output{tag};
    if (value.size() < 128U) {
        output.push_back(static_cast<std::uint8_t>(value.size()));
    } else if (value.size() < 256U) {
        output.push_back(0x81U);
        output.push_back(static_cast<std::uint8_t>(value.size()));
    } else {
        output.push_back(0x82U);
        output.push_back(static_cast<std::uint8_t>(value.size() >> 8U));
        output.push_back(static_cast<std::uint8_t>(value.size() & 0xffU));
    }
    append(output, value);
    return output;
}

Bytes concat(std::initializer_list<Bytes> values)
{
    Bytes output;
    for (const Bytes &value : values) append(output, value);
    return output;
}

Bytes name(std::string_view common_name)
{
    const Bytes oid_cn = tlv(0x06U, bytes({0x55U, 0x04U, 0x03U}));
    return tlv(0x30U, tlv(0x31U, tlv(0x30U, concat({oid_cn, tlv(0x0cU, text(common_name))}))));
}

void append_u24(Bytes &target, std::size_t value)
{
    target.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    target.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    target.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

Bytes handshake(std::uint8_t type, const Bytes &body)
{
    Bytes output{type};
    append_u24(output, body.size());
    append(output, body);
    return output;
}

Bytes record(const Bytes &payload)
{
    assert(payload.size() < 65536U);
    Bytes output{0x16U, 0x03U, 0x03U,
                 static_cast<std::uint8_t>(payload.size() >> 8U),
                 static_cast<std::uint8_t>(payload.size() & 0xffU)};
    append(output, payload);
    return output;
}

} // namespace

int main()
{
    const Bytes signature = tlv(0x30U, {});
    const Bytes validity = tlv(0x30U, concat({
        tlv(0x17U, text("260101000000Z")),
        tlv(0x17U, text("270101000000Z"))}));
    const Bytes san_names = tlv(0x30U, tlv(0x82U, text("www.example.test")));
    const Bytes san_extension = tlv(0x30U, concat({
        tlv(0x06U, bytes({0x55U, 0x1dU, 0x11U})),
        tlv(0x04U, san_names)}));
    const Bytes extensions = tlv(0xa3U, tlv(0x30U, san_extension));
    const Bytes tbs = tlv(0x30U, concat({
        tlv(0xa0U, tlv(0x02U, bytes({0x02U}))),
        tlv(0x02U, bytes({0x01U})),
        signature,
        name("Test Issuer"),
        validity,
        name("service.example.test"),
        tlv(0x30U, {}),
        extensions}));
    const Bytes certificate = tlv(0x30U, concat({tbs, signature, tlv(0x03U, bytes({0x00U}))}));
    Bytes certificate_body;
    append_u24(certificate_body, certificate.size() + 3U);
    append_u24(certificate_body, certificate.size());
    append(certificate_body, certificate);

    Bytes server_hello{0x03U, 0x03U};
    server_hello.insert(server_hello.end(), 32U, 0U);
    append(server_hello, bytes({0x00U, 0xc0U, 0x2fU, 0x00U}));
    const Bytes hello_extensions = bytes({
        0x00U, 0x2bU, 0x00U, 0x02U, 0x03U, 0x04U,
        0x00U, 0x10U, 0x00U, 0x05U, 0x00U, 0x03U, 0x02U, 'h', '2'});
    server_hello.push_back(0x00U);
    server_hello.push_back(static_cast<std::uint8_t>(hello_extensions.size()));
    append(server_hello, hello_extensions);

    Bytes response = record(handshake(0x02U, server_hello));
    append(response, record(handshake(0x0bU, certificate_body)));
    const skan::detect::TlsMetadata metadata = skan::detect::parse_tls_metadata(response);
    assert(metadata.detected);
    assert(metadata.protocol_version == "TLS 1.3");
    assert(metadata.certificate_subject == "CN=service.example.test");
    assert(metadata.certificate_issuer == "CN=Test Issuer");
    assert(metadata.certificate_not_before == "260101000000Z");
    assert(metadata.certificate_not_after == "270101000000Z");
    assert(metadata.certificate_san_names == std::vector<std::string>{"www.example.test"});
    assert(metadata.alpn == std::vector<std::string>{"h2"});

    assert(!skan::detect::parse_tls_metadata(bytes({0x16U, 0x03U})).detected);
    return 0;
}
