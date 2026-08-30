#include "detect/tls_metadata.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <new>
#include <string_view>

namespace skan::detect {
namespace {

constexpr std::size_t kMaximumTlsBytes = 64U << 10U;
constexpr std::size_t kMaximumCertificateBytes = 48U << 10U;
constexpr std::size_t kMaximumNames = 32U;
constexpr std::size_t kMaximumTextBytes = 1024U;

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>((static_cast<unsigned int>(bytes[offset]) << 8U) |
                                      static_cast<unsigned int>(bytes[offset + 1U]));
}

std::size_t read_u24(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return (static_cast<std::size_t>(bytes[offset]) << 16U) |
           (static_cast<std::size_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::size_t>(bytes[offset + 2U]);
}

std::string tls_version_name(std::uint16_t version)
{
    switch (version) {
    case 0x0301U:
        return "TLS 1.0";
    case 0x0302U:
        return "TLS 1.1";
    case 0x0303U:
        return "TLS 1.2";
    case 0x0304U:
        return "TLS 1.3";
    default:
        return {};
    }
}

struct DerValue final {
    std::uint8_t tag{0U};
    std::span<const std::uint8_t> value;
};

bool der_next(std::span<const std::uint8_t> input, std::size_t &offset, DerValue &value) noexcept
{
    if (offset + 2U > input.size()) {
        return false;
    }
    value.tag = input[offset++];
    std::size_t length = input[offset++];
    if ((length & 0x80U) != 0U) {
        const std::size_t length_bytes = length & 0x7fU;
        if (length_bytes == 0U || length_bytes > sizeof(std::size_t) || offset + length_bytes > input.size()) {
            return false;
        }
        length = 0U;
        for (std::size_t index = 0U; index < length_bytes; ++index) {
            if (length > (input.size() >> 8U)) {
                return false;
            }
            length = (length << 8U) | input[offset++];
        }
    }
    if (length > input.size() - offset) {
        return false;
    }
    value.value = input.subspan(offset, length);
    offset += length;
    return true;
}

std::string oid_text(std::span<const std::uint8_t> oid)
{
    if (oid.empty()) {
        return {};
    }
    std::string output = std::to_string(static_cast<unsigned int>(oid[0]) / 40U) + "." +
                         std::to_string(static_cast<unsigned int>(oid[0]) % 40U);
    std::uint64_t component = 0U;
    for (std::size_t index = 1U; index < oid.size(); ++index) {
        if (component > (UINT64_MAX >> 7U)) {
            return {};
        }
        component = (component << 7U) | static_cast<std::uint64_t>(oid[index] & 0x7fU);
        if ((oid[index] & 0x80U) == 0U) {
            output += "." + std::to_string(component);
            component = 0U;
        }
    }
    return component == 0U ? output : std::string{};
}

std::string asn1_text(const DerValue &value)
{
    if (value.value.size() > kMaximumTextBytes) {
        return {};
    }
    if (value.tag == 0x1eU) {
        std::string output;
        output.reserve(value.value.size() / 2U);
        for (std::size_t index = 0U; index + 1U < value.value.size(); index += 2U) {
            if (value.value[index] != 0U || value.value[index + 1U] < 0x20U) {
                return {};
            }
            output.push_back(static_cast<char>(value.value[index + 1U]));
        }
        return output;
    }
    if (value.tag != 0x0cU && value.tag != 0x13U && value.tag != 0x14U && value.tag != 0x16U &&
        value.tag != 0x17U && value.tag != 0x18U) {
        return {};
    }
    return {reinterpret_cast<const char *>(value.value.data()), value.value.size()};
}

const char *attribute_label(std::string_view oid) noexcept
{
    if (oid == "2.5.4.3") return "CN";
    if (oid == "2.5.4.6") return "C";
    if (oid == "2.5.4.7") return "L";
    if (oid == "2.5.4.8") return "ST";
    if (oid == "2.5.4.10") return "O";
    if (oid == "2.5.4.11") return "OU";
    return nullptr;
}

std::string parse_name(std::span<const std::uint8_t> encoded)
{
    std::size_t offset = 0U;
    DerValue sequence;
    if (!der_next(encoded, offset, sequence) || sequence.tag != 0x30U || offset != encoded.size()) {
        return {};
    }
    std::string output;
    std::size_t set_offset = 0U;
    while (set_offset < sequence.value.size()) {
        DerValue set;
        if (!der_next(sequence.value, set_offset, set) || set.tag != 0x31U) {
            return {};
        }
        std::size_t pair_offset = 0U;
        DerValue pair;
        if (!der_next(set.value, pair_offset, pair) || pair.tag != 0x30U) {
            return {};
        }
        std::size_t attribute_offset = 0U;
        DerValue oid;
        DerValue text;
        if (!der_next(pair.value, attribute_offset, oid) || oid.tag != 0x06U ||
            !der_next(pair.value, attribute_offset, text)) {
            return {};
        }
        const std::string oid_value = oid_text(oid.value);
        const char *label = attribute_label(oid_value);
        const std::string decoded = asn1_text(text);
        if (label != nullptr && !decoded.empty()) {
            if (!output.empty()) output += ", ";
            output += label;
            output += '=';
            output += decoded;
            if (output.size() > kMaximumTextBytes) return {};
        }
    }
    return output;
}

void parse_san_extension(std::span<const std::uint8_t> encoded, TlsMetadata &metadata)
{
    std::size_t offset = 0U;
    DerValue names;
    if (!der_next(encoded, offset, names) || names.tag != 0x30U) return;
    std::size_t name_offset = 0U;
    while (name_offset < names.value.size() && metadata.certificate_san_names.size() < kMaximumNames) {
        DerValue name;
        if (!der_next(names.value, name_offset, name)) return;
        if (name.tag == 0x82U && !name.value.empty() && name.value.size() <= 253U) {
            metadata.certificate_san_names.emplace_back(
                reinterpret_cast<const char *>(name.value.data()), name.value.size());
        }
    }
}

void parse_extensions(std::span<const std::uint8_t> encoded, TlsMetadata &metadata)
{
    std::size_t outer_offset = 0U;
    DerValue sequence;
    if (!der_next(encoded, outer_offset, sequence) || sequence.tag != 0x30U) return;
    std::size_t offset = 0U;
    while (offset < sequence.value.size()) {
        DerValue extension;
        if (!der_next(sequence.value, offset, extension) || extension.tag != 0x30U) return;
        std::size_t field_offset = 0U;
        DerValue oid;
        DerValue value;
        if (!der_next(extension.value, field_offset, oid) || oid.tag != 0x06U) continue;
        if (!der_next(extension.value, field_offset, value)) continue;
        if (value.tag == 0x01U && !der_next(extension.value, field_offset, value)) continue;
        if (oid_text(oid.value) == "2.5.29.17" && value.tag == 0x04U) {
            parse_san_extension(value.value, metadata);
        }
    }
}

void parse_certificate(std::span<const std::uint8_t> der, TlsMetadata &metadata)
{
    if (der.empty() || der.size() > kMaximumCertificateBytes) return;
    std::size_t certificate_offset = 0U;
    DerValue certificate;
    if (!der_next(der, certificate_offset, certificate) || certificate.tag != 0x30U) return;
    std::size_t outer_offset = 0U;
    DerValue tbs;
    if (!der_next(certificate.value, outer_offset, tbs) || tbs.tag != 0x30U) return;
    std::size_t offset = 0U;
    DerValue field;
    if (!der_next(tbs.value, offset, field)) return;
    if (field.tag == 0xa0U && !der_next(tbs.value, offset, field)) return;
    // Serial number is in field; signature algorithm follows it.
    if (!der_next(tbs.value, offset, field)) return;
    const std::size_t issuer_start = offset;
    if (!der_next(tbs.value, offset, field) || field.tag != 0x30U) return;
    metadata.certificate_issuer = parse_name(tbs.value.subspan(issuer_start, offset - issuer_start));
    DerValue validity;
    if (!der_next(tbs.value, offset, validity) || validity.tag != 0x30U) return;
    std::size_t validity_offset = 0U;
    DerValue not_before;
    DerValue not_after;
    if (der_next(validity.value, validity_offset, not_before) &&
        der_next(validity.value, validity_offset, not_after)) {
        metadata.certificate_not_before = asn1_text(not_before);
        metadata.certificate_not_after = asn1_text(not_after);
    }
    const std::size_t subject_start = offset;
    if (!der_next(tbs.value, offset, field) || field.tag != 0x30U) return;
    metadata.certificate_subject = parse_name(tbs.value.subspan(subject_start, offset - subject_start));
    // SubjectPublicKeyInfo.
    if (!der_next(tbs.value, offset, field) || field.tag != 0x30U) return;
    while (offset < tbs.value.size()) {
        if (!der_next(tbs.value, offset, field)) return;
        if (field.tag == 0xa3U) {
            parse_extensions(field.value, metadata);
            return;
        }
    }
}

void parse_server_hello(std::span<const std::uint8_t> hello, TlsMetadata &metadata)
{
    if (hello.size() < 38U) return;
    metadata.protocol_version = tls_version_name(read_u16(hello, 0U));
    std::size_t offset = 34U;
    const std::size_t session_length = hello[offset++];
    if (session_length > hello.size() - offset || hello.size() - offset - session_length < 3U) return;
    offset += session_length + 3U; // cipher suite and compression
    if (offset == hello.size()) return;
    if (hello.size() - offset < 2U) return;
    const std::size_t extensions_length = read_u16(hello, offset);
    offset += 2U;
    if (extensions_length > hello.size() - offset) return;
    const std::size_t end = offset + extensions_length;
    while (offset + 4U <= end) {
        const std::uint16_t type = read_u16(hello, offset);
        const std::size_t length = read_u16(hello, offset + 2U);
        offset += 4U;
        if (length > end - offset) return;
        const auto value = hello.subspan(offset, length);
        if (type == 0x002bU && value.size() == 2U) {
            metadata.protocol_version = tls_version_name(read_u16(value, 0U));
        } else if (type == 0x0010U && value.size() >= 3U) {
            std::size_t alpn_offset = 2U;
            while (alpn_offset < value.size() && metadata.alpn.size() < kMaximumNames) {
                const std::size_t name_length = value[alpn_offset++];
                if (name_length == 0U || name_length > value.size() - alpn_offset) break;
                metadata.alpn.emplace_back(
                    reinterpret_cast<const char *>(value.data() + alpn_offset), name_length);
                alpn_offset += name_length;
            }
        }
        offset += length;
    }
}

void parse_certificate_message(std::span<const std::uint8_t> message, TlsMetadata &metadata)
{
    if (message.size() < 6U) return;
    const std::size_t list_length = read_u24(message, 0U);
    if (list_length > message.size() - 3U) return;
    const std::size_t certificate_length = read_u24(message, 3U);
    if (certificate_length > message.size() - 6U) return;
    parse_certificate(message.subspan(6U, certificate_length), metadata);
}

} // namespace

TlsMetadata parse_tls_metadata(std::span<const std::uint8_t> response)
{
    TlsMetadata metadata;
    if (response.size() < 5U || response.size() > kMaximumTlsBytes) return metadata;
    try {
        std::vector<std::uint8_t> handshake;
        handshake.reserve(std::min(response.size(), kMaximumTlsBytes));
        std::size_t offset = 0U;
        while (offset + 5U <= response.size()) {
            const std::uint8_t type = response[offset];
            const std::uint16_t record_version = read_u16(response, offset + 1U);
            const std::size_t length = read_u16(response, offset + 3U);
            offset += 5U;
            if (length > response.size() - offset) break;
            if (type == 0x15U || type == 0x16U) {
                metadata.detected = true;
                if (metadata.protocol_version.empty()) {
                    metadata.protocol_version = tls_version_name(record_version);
                }
            }
            if (type == 0x16U && length <= kMaximumTlsBytes - handshake.size()) {
                handshake.insert(handshake.end(), response.begin() + static_cast<std::ptrdiff_t>(offset),
                                 response.begin() + static_cast<std::ptrdiff_t>(offset + length));
            }
            offset += length;
        }
        std::size_t handshake_offset = 0U;
        const std::span<const std::uint8_t> messages{handshake};
        while (handshake_offset + 4U <= messages.size()) {
            const std::uint8_t type = messages[handshake_offset];
            const std::size_t length = read_u24(messages, handshake_offset + 1U);
            handshake_offset += 4U;
            if (length > messages.size() - handshake_offset) break;
            const auto message = messages.subspan(handshake_offset, length);
            if (type == 0x02U) parse_server_hello(message, metadata);
            if (type == 0x0bU) parse_certificate_message(message, metadata);
            handshake_offset += length;
        }
    } catch (const std::bad_alloc &) {
        return TlsMetadata{};
    }
    return metadata;
}

} // namespace skan::detect
