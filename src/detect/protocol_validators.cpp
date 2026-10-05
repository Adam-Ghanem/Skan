#include "detect/protocol_validators.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <set>
#include <vector>

namespace skan::detect
{
namespace
{
constexpr std::size_t kLimit = 8192U;
unsigned int byte(std::string_view s, std::size_t p) noexcept { return static_cast<unsigned char>(s[p]); }
std::uint32_t number(std::string_view s, std::size_t p, unsigned int width, bool little = false) noexcept
{
    std::uint32_t n = 0U;
    for (unsigned int i = 0U; i < width; ++i)
        n = (n << 8U) | byte(s, p + (little ? width - 1U - i : i));
    return n;
}
bool decimal(std::string_view s, std::size_t &n) noexcept
{
    if (s.empty())
        return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}
bool text(std::string_view s) noexcept
{
    if (s.empty() || s.size() > 1024U)
        return false;
    for (unsigned char c : s)
        if (c < 32U || c == 127U)
            return false;
    return true;
}
bool utf8(std::string_view s) noexcept
{
    for (std::size_t p = 0U; p < s.size();)
    {
        auto c = byte(s, p++);
        if (c < 128U)
            continue;
        unsigned int remaining = 0U, value = 0U, minimum = 0U;
        if (c >= 0xc2U && c <= 0xdfU)
        {
            remaining = 1U;
            value = c & 31U;
            minimum = 128U;
        }
        else if (c >= 0xe0U && c <= 0xefU)
        {
            remaining = 2U;
            value = c & 15U;
            minimum = 2048U;
        }
        else if (c >= 0xf0U && c <= 0xf4U)
        {
            remaining = 3U;
            value = c & 7U;
            minimum = 65536U;
        }
        else
            return false;
        if (remaining > s.size() - p)
            return false;
        for (unsigned int i = 0U; i < remaining; ++i)
        {
            c = byte(s, p++);
            if ((c & 0xc0U) != 0x80U)
                return false;
            value = (value << 6U) | (c & 63U);
        }
        if (value < minimum || value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU))
            return false;
    }
    return true;
}
bool version(std::string_view s) noexcept
{
    if (s.empty() || s.size() > 128U || s.front() < '0' || s.front() > '9')
        return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' ||
              c == '-' || c == '_' || c == '+' || c == '~'))
            return false;
    return true;
}
std::string_view line(std::string_view s) noexcept
{
    const auto n = s.find('\n');
    if (n == std::string_view::npos)
        return {};
    auto out = s.substr(0U, n);
    if (out.ends_with('\r'))
        out.remove_suffix(1U);
    return text(out) ? out : std::string_view{};
}
std::optional<std::string_view> first_frame(std::string_view s, unsigned int prefix, bool little,
                                            bool last_bit = false)
{
    if (s.size() < prefix)
        return std::nullopt;
    auto n = number(s, 0U, prefix, little);
    if (last_bit)
    {
        if (!(n & 0x80000000U))
            return std::nullopt;
        n &= 0x7fffffffU;
    }
    if (n == 0U || n > kLimit - prefix || n > s.size() - prefix)
        return std::nullopt;
    return s.substr(prefix, n);
}
ProtocolIdentity identity(std::string_view family, std::string_view product, std::string_view id)
{
    ProtocolIdentity out;
    out.service = family;
    out.product = product;
    out.validator = id;
    return out;
}
// Definite-length BER reader. Reject indefinite/overflow/truncated lengths;
// caller selects the expected application tag and validates its fields.
struct Tlv
{
    unsigned int tag;
    std::string_view body;
};
bool tlv(std::string_view s, std::size_t &p, Tlv &out)
{
    if (s.size() - p < 2U)
        return false;
    out.tag = byte(s, p++);
    if ((out.tag & 31U) == 31U)
        return false;
    std::size_t length = byte(s, p++);
    if (length & 128U)
    {
        const auto count = length & 127U;
        if (count == 0U || count > 4U || count > s.size() - p)
            return false;
        length = 0U;
        for (std::size_t i = 0U; i < count; ++i)
            length = (length << 8U) | byte(s, p++);
    }
    if (length > s.size() - p)
        return false;
    out.body = s.substr(p, length);
    p += length;
    return true;
}
bool whole_tlv(std::string_view s, unsigned int tag, std::string_view &body)
{
    std::size_t p = 0U;
    Tlv t{};
    if (!tlv(s, p, t) || p != s.size() || t.tag != tag)
        return false;
    body = t.body;
    return true;
}
bool ber_tree(std::string_view s, std::size_t depth, std::size_t &nodes)
{
    if (depth > 16U)
        return false;
    std::size_t p = 0U;
    while (p < s.size())
    {
        Tlv t{};
        if (++nodes > 512U || !tlv(s, p, t))
            return false;
        if ((t.tag & 32U) && !ber_tree(t.body, depth + 1U, nodes))
            return false;
    }
    return true;
}
// Strict bounded BSON, including unused values. All fields within each object
// are unique. Unsupported types fail closed instead of scanning embedded bytes.
struct BsonIdentity
{
    std::string version;
    bool ok{false};
    bool have_ok{false};
};
bool bson(std::string_view s, std::size_t depth, std::size_t &nodes, BsonIdentity *out = nullptr)
{
    if (depth > 16U || s.size() < 5U || number(s, 0U, 4U, true) != s.size() || s.back() != 0)
        return false;
    std::size_t p = 4U;
    std::set<std::string_view> keys;
    while (p < s.size() - 1U)
    {
        if (++nodes > 512U)
            return false;
        const auto type = byte(s, p++);
        const auto end = s.find('\0', p);
        if (end == std::string_view::npos || end >= s.size() - 1U || end - p > 128U)
            return false;
        const auto key = s.substr(p, end - p);
        if (!utf8(key) || !keys.insert(key).second)
            return false;
        p = end + 1U;
        std::size_t size = 0U;
        switch (type)
        {
        case 1U:
        case 9U:
        case 17U:
        case 18U:
            size = 8U;
            break;
        case 16U:
            size = 4U;
            break;
        case 7U:
            size = 12U;
            break;
        case 19U:
            size = 16U;
            break;
        case 8U:
            size = 1U;
            if (p >= s.size() - 1U || byte(s, p) > 1U)
                return false;
            break;
        case 6U:
        case 10U:
        case 127U:
        case 255U:
            size = 0U;
            break;
        case 2U:
        case 13U:
        case 14U:
        {
            if (s.size() - p < 4U)
                return false;
            const auto n = number(s, p, 4U, true);
            if (n == 0U || n > s.size() - p - 4U || s[p + 4U + n - 1U] != 0)
                return false;
            const auto value = s.substr(p + 4U, n - 1U);
            if (!utf8(value))
                return false;
            if (out && key == "version" && type == 2U)
            {
                if (!version(value))
                    return false;
                out->version = value;
            }
            size = 4U + n;
            break;
        }
        case 3U:
        case 4U:
        {
            if (s.size() - p < 4U)
                return false;
            const auto n = number(s, p, 4U, true);
            if (n > s.size() - p || !bson(s.substr(p, n), depth + 1U, nodes))
                return false;
            size = n;
            break;
        }
        case 5U:
        {
            if (s.size() - p < 5U)
                return false;
            const auto n = number(s, p, 4U, true);
            if (n > s.size() - p - 5U)
                return false;
            size = 5U + n;
            break;
        }
        case 11U:
        {
            auto e = s.find('\0', p);
            if (e == std::string_view::npos)
                return false;
            e = s.find('\0', e + 1U);
            if (e == std::string_view::npos)
                return false;
            size = e + 1U - p;
            break;
        }
        default:
            return false;
        }
        if (size > s.size() - 1U - p)
            return false;
        if (out && key == "ok")
        {
            out->have_ok = true;
            if (type == 1U)
            { // IEEE754 1.0 or 0.0, little endian.
                const auto low = number(s, p, 4U, true), high = number(s, p + 4U, 4U, true);
                if (low != 0U || !(high == 0U || high == 0x3ff00000U))
                    return false;
                out->ok = high != 0U;
            }
            else if (type == 16U || type == 18U)
            {
                if (number(s, p, 4U, true) > 1U || (type == 18U && number(s, p + 4U, 4U, true) != 0U))
                    return false;
                out->ok = byte(s, p) == 1U;
            }
            else
                return false;
        }
        p += size;
    }
    return p == s.size() - 1U;
}
std::uint32_t crc32c(std::string_view bytes) noexcept
{
    std::uint32_t crc = ~0U;
    for (unsigned char b : bytes)
    {
        crc ^= b;
        for (unsigned int i = 0U; i < 8U; ++i)
            crc = (crc >> 1U) ^ ((crc & 1U) ? 0x82f63b78U : 0U);
    }
    return ~crc;
}
std::optional<ProtocolIdentity> mongo(std::string_view q, std::string_view s)
{
    if (q.size() < 26U || number(q, 0U, 4U, true) != q.size() || number(q, 12U, 4U, true) != 2013U ||
        number(q, 16U, 4U, true) != 0U || byte(q, 20U) != 0U)
        return std::nullopt;
    std::size_t nodes = 0U;
    if (!bson(q.substr(21U), 0U, nodes) || s.size() < 26U)
        return std::nullopt;
    const auto size = number(s, 0U, 4U, true);
    if (size < 26U || size > s.size() || size > kLimit ||
        number(s, 8U, 4U, true) != number(q, 4U, 4U, true) || number(s, 12U, 4U, true) != 2013U)
        return std::nullopt;
    s = s.substr(0U, size);
    const auto flags = number(s, 16U, 4U, true);
    if (flags & 0x0000fffeU)
        return std::nullopt;
    if (flags & 1U)
    {
        if (s.size() < 30U || crc32c(s.substr(0U, s.size() - 4U)) != number(s, s.size() - 4U, 4U, true))
            return std::nullopt;
        s.remove_suffix(4U);
    }
    if (byte(s, 20U) != 0U)
        return std::nullopt;
    BsonIdentity parsed;
    nodes = 0U;
    if (!bson(s.substr(21U), 0U, nodes, &parsed) || !parsed.have_ok)
        return std::nullopt;
    auto out = identity("mongodb", "MongoDB-compatible", "mongodb-opmsg-bson-v1");
    if (parsed.ok)
    {
        out.version = parsed.version;
        if (!out.version.empty())
            out.version_source = "BSON.version";
    }
    return out;
}
std::optional<ProtocolIdentity> mysql(std::string_view s)
{
    if (s.size() < 5U || byte(s, 3U) != 0U || byte(s, 4U) != 10U)
        return std::nullopt;
    const auto payload = number(s, 0U, 3U, true);
    if (payload > s.size() - 4U || payload < 19U)
        return std::nullopt;
    s = s.substr(4U, payload);
    const auto end = s.find('\0', 1U);
    if (end == std::string_view::npos || !version(s.substr(1U, end - 1U)))
        return std::nullopt;
    const auto p = end + 1U;
    if (s.size() - p < 15U || byte(s, p + 12U) != 0U)
        return std::nullopt;
    const auto caps = number(s, p + 13U, 2U, true);
    if (s.size() - p != 15U)
    {
        if (s.size() - p < 31U)
            return std::nullopt;
        for (std::size_t i = p + 21U; i < p + ((caps & 1U) ? 31U : 27U); ++i)
            if (byte(s, i) != 0U)
                return std::nullopt;
        const auto extended = number(s, p + 18U, 2U, true);
        const auto authlen = byte(s, p + 20U);
        std::size_t rest = p + 31U;
        if (caps & 0x8000U)
        {
            const auto n = std::max(13U, authlen > 8U ? authlen - 8U : 0U);
            if (n > s.size() - rest)
                return std::nullopt;
            rest += n;
        }
        if (extended & 8U)
        {
            const auto plugin_end = s.find('\0', rest);
            if (plugin_end == std::string_view::npos || !text(s.substr(rest, plugin_end - rest)))
                return std::nullopt;
            rest = plugin_end + 1U;
        }
        if (rest != s.size())
            return std::nullopt;
    }
    auto out = identity("mysql",
                        s.substr(1U, end - 1U).find("MariaDB") != std::string_view::npos ? "MariaDB"
                                                                                         : "MySQL-compatible",
                        "mysql-handshake-v10-v1");
    out.version = s.substr(1U, end - 1U);
    out.version_source = "server-version";
    out.protocol_version = "10";
    return out;
}
std::optional<ProtocolIdentity> cassandra(std::string_view q, std::string_view s)
{
    if (q.size() != 9U || byte(q, 0U) != 4U || byte(q, 1U) != 0U || byte(q, 4U) != 5U ||
        number(q, 5U, 4U) != 0U || s.size() < 11U || byte(s, 0U) != 0x84U || byte(s, 1U) != 0U ||
        s.substr(2U, 2U) != q.substr(2U, 2U) || byte(s, 4U) != 6U)
        return std::nullopt;
    const auto size = number(s, 5U, 4U);
    if (size > s.size() - 9U || size < 2U)
        return std::nullopt;
    s = s.substr(9U, size);
    std::size_t p = 2U;
    const auto count = number(s, 0U, 2U);
    bool cql = false;
    std::set<std::string_view> keys;
    const auto string = [&](std::string_view &out)
    {
        if (s.size() - p < 2U)
            return false;
        const auto n = number(s, p, 2U);
        p += 2U;
        if (n > s.size() - p || n > 1024U)
            return false;
        out = s.substr(p, n);
        p += n;
        return text(out);
    };
    if (count > 64U)
        return std::nullopt;
    for (unsigned int i = 0U; i < count; ++i)
    {
        std::string_view key;
        if (!string(key) || !keys.insert(key).second || s.size() - p < 2U)
            return std::nullopt;
        const auto values = number(s, p, 2U);
        p += 2U;
        if (values > 64U)
            return std::nullopt;
        for (unsigned int j = 0U; j < values; ++j)
        {
            std::string_view value;
            if (!string(value))
                return std::nullopt;
            if (key == "CQL_VERSION" && version(value))
                cql = true;
        }
    }
    if (p != s.size() || !cql)
        return std::nullopt;
    auto out = identity("cassandra", "Cassandra-compatible", "cassandra-supported-v4-v1");
    out.protocol_version = "4";
    return out;
}
std::optional<ProtocolIdentity> ldap(std::string_view q, std::string_view s)
{
    std::string_view request, response;
    if (!whole_tlv(q, 0x30U, request))
        return std::nullopt;
    std::size_t p = 0U;
    Tlv id{}, bind{};
    if (!tlv(request, p, id) || id.tag != 2U || id.body.empty() || !tlv(request, p, bind) ||
        bind.tag != 0x60U || p != request.size())
        return std::nullopt;
    std::size_t bindpos = 0U;
    Tlv ver{}, name{}, auth{};
    if (!tlv(bind.body, bindpos, ver) || ver.tag != 2U || ver.body != std::string_view{"\x03", 1U} ||
        !tlv(bind.body, bindpos, name) || name.tag != 4U || !name.body.empty() ||
        !tlv(bind.body, bindpos, auth) || auth.tag != 0x80U || !auth.body.empty() ||
        bindpos != bind.body.size())
        return std::nullopt;
    std::size_t r = 0U;
    Tlv root{};
    if (!tlv(s, r, root) || root.tag != 0x30U)
        return std::nullopt;
    response = root.body;
    p = 0U;
    Tlv rid{}, result{};
    if (!tlv(response, p, rid) || rid.tag != 2U || rid.body != id.body || !tlv(response, p, result) ||
        result.tag != 0x61U)
        return std::nullopt;
    std::size_t nodes = 0U;
    if (!ber_tree(response, 0U, nodes))
        return std::nullopt;
    p = 0U;
    Tlv code{}, dn{}, diagnostic{};
    if (!tlv(result.body, p, code) || code.tag != 10U || code.body.size() != 1U ||
        byte(code.body, 0U) > 80U || !tlv(result.body, p, dn) || dn.tag != 4U ||
        !tlv(result.body, p, diagnostic) || diagnostic.tag != 4U)
        return std::nullopt;
    if (p < result.body.size())
    {
        Tlv referral{};
        if (!tlv(result.body, p, referral) || referral.tag != 0xa3U || p != result.body.size())
            return std::nullopt;
    }
    auto out = identity("ldap", "LDAPv3", "ldap-bind-ber-v1");
    out.protocol_version = "3";
    return out;
}
std::optional<ProtocolIdentity> rdp(std::string_view q, std::string_view s)
{
    if (q.size() != 19U || q.substr(0U, 2U) != std::string_view{"\x03\0", 2U} || number(q, 2U, 2U) != 19U ||
        byte(q, 5U) != 0xe0U || s.size() < 11U || s.substr(0U, 2U) != q.substr(0U, 2U))
        return std::nullopt;
    const auto size = number(s, 2U, 2U);
    if (size > s.size() || size < 11U || size != static_cast<std::size_t>(byte(s, 4U)) + 5U ||
        byte(s, 5U) != 0xd0U || s.substr(6U, 2U) != q.substr(8U, 2U) || byte(s, 10U) != 0U)
        return std::nullopt;
    if (size == 11U)
        return identity("ms-wbt-server", "RDP", "rdp-x224-negotiation-v1");
    if (size != 19U || !(byte(s, 11U) == 2U || byte(s, 11U) == 3U) || number(s, 13U, 2U, true) != 8U)
        return std::nullopt;
    const auto selected = number(s, 15U, 4U, true);
    if (byte(s, 11U) == 2U)
    {
        if (!(selected == 0U || selected == 1U || selected == 2U || selected == 8U) ||
            (selected && !(selected & number(q, 15U, 4U, true))))
            return std::nullopt;
    }
    else if (selected < 1U || selected > 6U)
        return std::nullopt;
    auto out = identity("ms-wbt-server", "RDP", "rdp-x224-negotiation-v1");
    out.extra = byte(s, 11U) == 2U ? "negotiation-response" : "negotiation-failure";
    return out;
}
std::optional<ProtocolIdentity> smb(std::string_view q, std::string_view s)
{
    if (q.size() < 106U || q.substr(4U, 4U) != std::string_view{"\xfeSMB", 4U} ||
        number(q, 0U, 4U) != q.size() - 4U || number(q, 16U, 2U, true) != 0U ||
        number(q, 68U, 2U, true) != 36U || number(q, 70U, 2U, true) != 1U ||
        number(q, 104U, 2U, true) != 0x0202U)
        return std::nullopt;
    auto frame = first_frame(s, 4U, false);
    if (!frame || byte(s, 0U) != 0U || frame->size() < 128U)
        return std::nullopt;
    const auto b = *frame;
    if (b.substr(0U, 4U) != std::string_view{"\xfeSMB", 4U} || number(b, 4U, 2U, true) != 64U ||
        number(b, 8U, 4U, true) != 0U || number(b, 12U, 2U, true) != 0U || !(number(b, 16U, 4U, true) & 1U) ||
        number(b, 20U, 4U, true) != 0U || b.substr(24U, 8U) != q.substr(28U, 8U) ||
        number(b, 64U, 2U, true) != 65U || number(b, 68U, 2U, true) != 0x0202U)
        return std::nullopt;
    const auto offset = number(b, 120U, 2U, true), length = number(b, 122U, 2U, true);
    if (length && (offset < 128U || offset > b.size() || length > b.size() - offset))
        return std::nullopt;
    auto out = identity("microsoft-ds", "SMB2", "smb2-negotiate-v1");
    out.protocol_version = "2.0.2";
    return out;
}
std::optional<ProtocolIdentity> nfs(std::string_view q, std::string_view s)
{
    if (q.size() != 44U || number(q, 0U, 4U) != 0x80000028U || number(q, 8U, 4U) != 0U ||
        number(q, 12U, 4U) != 2U || number(q, 16U, 4U) != 100003U || number(q, 20U, 4U) != 3U ||
        number(q, 24U, 4U) != 0U)
        return std::nullopt;
    auto frame = first_frame(s, 4U, false, true);
    if (!frame || frame->size() < 24U)
        return std::nullopt;
    const auto b = *frame;
    if (b.substr(0U, 4U) != q.substr(4U, 4U) || number(b, 4U, 4U) != 1U || number(b, 8U, 4U) != 0U)
        return std::nullopt;
    const auto length = number(b, 16U, 4U);
    if (length > 400U)
        return std::nullopt;
    const std::size_t status = 20U + ((length + 3U) & ~3U);
    if (status + 4U != b.size() || number(b, status, 4U) != 0U)
        return std::nullopt;
    auto out = identity("nfs", "NFS", "onc-rpc-nfs-null-v1");
    out.protocol_version = "3";
    return out;
}
std::optional<ProtocolIdentity> dns(std::string_view q, std::string_view s)
{
    auto request = first_frame(q, 2U, false), response = first_frame(s, 2U, false);
    if (!request || !response || request->size() < 12U || response->size() < 12U)
        return std::nullopt;
    const auto a = *request, b = *response;
    if (q.size() != a.size() + 2U || (number(a, 2U, 2U) & 0x8000U) || !(number(b, 2U, 2U) & 0x8000U) ||
        a.substr(0U, 2U) != b.substr(0U, 2U) || ((number(a, 2U, 2U) ^ number(b, 2U, 2U)) & 0x7800U) ||
        number(a, 4U, 2U) != 1U || number(b, 4U, 2U) != 1U)
        return std::nullopt;
    // Validate every DNS name including compression references. Pointer cycles,
    // forward references and >255-byte expanded names are rejected.
    const auto name = [&](std::size_t &p)
    {
        std::size_t cursor = p, steps = 0U, expanded = 0U;
        bool jumped = false;
        while (cursor < b.size() && ++steps <= 128U)
        {
            const auto label = byte(b, cursor++);
            if (!label)
            {
                if (!jumped)
                    p = cursor;
                return true;
            }
            if ((label & 0xc0U) == 0xc0U)
            {
                if (cursor >= b.size())
                    return false;
                const auto target = ((label & 63U) << 8U) | byte(b, cursor++);
                if (target >= cursor - 2U || target < 12U)
                    return false;
                if (!jumped)
                    p = cursor;
                jumped = true;
                cursor = target;
            }
            else
            {
                if (label > 63U || label > b.size() - cursor || (expanded += label + 1U) > 255U)
                    return false;
                cursor += label;
            }
        }
        return false;
    };
    std::size_t p = 12U;
    if (!name(p) || b.size() - p < 4U)
        return std::nullopt;
    p += 4U;
    if (a.size() < 12U || p - 12U > a.size() - 12U || b.substr(12U, p - 12U) != a.substr(12U))
        return std::nullopt;
    const auto records = number(b, 6U, 2U) + number(b, 8U, 2U) + number(b, 10U, 2U);
    if (records > 128U)
        return std::nullopt;
    for (unsigned int i = 0U; i < records; ++i)
    {
        if (!name(p) || b.size() - p < 10U)
            return std::nullopt;
        const auto n = number(b, p + 8U, 2U);
        p += 10U;
        if (n > b.size() - p)
            return std::nullopt;
        p += n;
    }
    if (p != b.size())
        return std::nullopt;
    return identity("dns", "DNS-over-TCP", "dns-tcp-message-v1");
}
std::optional<ProtocolIdentity> kerberos(std::string_view q, std::string_view s)
{
    auto request = first_frame(q, 4U, false), response = first_frame(s, 4U, false);
    if (!request || !response || q.size() != request->size() + 4U || request->empty() ||
        byte(*request, 0U) != 0x6aU)
        return std::nullopt;
    std::string_view application;
    const auto b = *response;
    if (b.empty() || !(byte(b, 0U) == 0x7eU || byte(b, 0U) == 0x6bU) ||
        !whole_tlv(b, byte(b, 0U), application))
        return std::nullopt;
    std::string_view sequence;
    if (!whole_tlv(application, 0x30U, sequence))
        return std::nullopt;
    std::size_t nodes = 0U;
    if (!ber_tree(sequence, 0U, nodes))
        return std::nullopt;
    std::size_t p = 0U;
    Tlv pv{}, msg{};
    std::string_view pvint, msgint;
    const bool error = byte(b, 0U) == 0x7eU;
    if (!tlv(sequence, p, pv) || pv.tag != (error ? 0xa0U : 0xa1U) || !whole_tlv(pv.body, 2U, pvint) ||
        pvint != std::string_view{"\x05", 1U} || !tlv(sequence, p, msg) ||
        msg.tag != (error ? 0xa1U : 0xa2U) || !whole_tlv(msg.body, 2U, msgint) ||
        msgint != std::string_view{error ? "\x1e" : "\x0b", 1U})
        return std::nullopt;

    // Validate the mandatory outer schema, not merely two discriminator TLVs.
    std::array<std::string_view, 13U> fields{};
    p = 0U;
    unsigned int previous = 0U;
    bool first = true;
    while (p < sequence.size())
    {
        Tlv field{};
        if (!tlv(sequence, p, field) || field.tag < 0xa0U || field.tag > 0xacU)
            return std::nullopt;
        const auto id = field.tag - 0xa0U;
        if ((!first && id <= previous) || !fields[id].empty())
            return std::nullopt;
        fields[id] = field.body;
        previous = id;
        first = false;
    }
    const auto wrapped = [&](unsigned int id, unsigned int tag)
    {
        std::string_view value;
        return !fields[id].empty() && whole_tlv(fields[id], tag, value) && !value.empty();
    };
    const auto integer = [&](unsigned int id)
    {
        std::string_view value;
        return whole_tlv(fields[id], 2U, value) && !value.empty() && value.size() <= 5U &&
               !(byte(value, 0U) & 128U);
    };
    const auto principal = [&](unsigned int id)
    {
        std::string_view body;
        if (!whole_tlv(fields[id], 0x30U, body))
            return false;
        std::size_t position = 0U;
        Tlv type{}, names{};
        std::string_view value, list;
        if (!tlv(body, position, type) || type.tag != 0xa0U || !whole_tlv(type.body, 2U, value) ||
            value.empty() || !tlv(body, position, names) || names.tag != 0xa1U ||
            !whole_tlv(names.body, 0x30U, list) || position != body.size() || list.empty())
            return false;
        position = 0U;
        unsigned int count = 0U;
        while (position < list.size())
        {
            Tlv name{};
            if (++count > 16U || !tlv(list, position, name) || name.tag != 0x1bU || !text(name.body))
                return false;
        }
        return true;
    };
    if (error)
    {
        std::string_view timestamp;
        if (!wrapped(4U, 0x18U) || !whole_tlv(fields[4U], 0x18U, timestamp) || timestamp.size() != 15U ||
            timestamp.back() != 'Z' || !integer(5U) || !integer(6U) || !wrapped(9U, 0x1bU) || !principal(10U))
            return std::nullopt;
        for (char c : timestamp.substr(0U, 14U))
            if (c < '0' || c > '9')
                return std::nullopt;
    }
    else
    {
        if (!wrapped(4U, 0x1bU) || !principal(5U) || !wrapped(6U, 0x61U) || !wrapped(7U, 0x30U))
            return std::nullopt;
    }

    auto out = identity("kerberos", "Kerberos-v5", "kerberos-tcp-ber-v1");
    out.protocol_version = "5";
    out.extra = error ? "KRB-ERROR" : "AS-REP";
    return out;
}
// AMQP field tables have independent lengths and typed values. Validate every
// entry, including unused capabilities, before extracting explicit properties.
struct AmqpProperties
{
    std::string product, version;
};
bool amqp_fields(std::string_view s, unsigned int depth, std::size_t &nodes, bool array,
                 AmqpProperties *properties = nullptr)
{
    if (depth > 16U)
        return false;
    std::size_t p = 0U;
    std::set<std::string_view> names;
    while (p < s.size())
    {
        if (++nodes > 512U)
            return false;
        std::string_view name;
        if (!array)
        {
            const auto n = byte(s, p++);
            if (n > s.size() - p)
                return false;
            name = s.substr(p, n);
            p += n;
            if (name.empty() || !utf8(name) || !names.insert(name).second)
                return false;
        }
        if (p == s.size())
            return false;
        const auto type = byte(s, p++);
        std::size_t n = 0U;
        switch (type)
        {
        case 't':
            if (p == s.size() || byte(s, p) > 1U)
                return false;
            [[fallthrough]];
        case 'b':
        case 'B':
            n = 1U;
            break;
        case 's':
        case 'U':
        case 'u':
            n = 2U;
            break;
        case 'I':
        case 'i':
        case 'f':
            n = 4U;
            break;
        case 'L':
        case 'l':
        case 'd':
        case 'T':
            n = 8U;
            break;
        case 'D':
            n = 5U;
            break;
        case 'V':
            break;
        case 'S':
        case 'x':
        case 'F':
        case 'A':
        {
            if (s.size() - p < 4U)
                return false;
            const auto length = number(s, p, 4U);
            p += 4U;
            if (length > s.size() - p)
                return false;
            const auto value = s.substr(p, length);
            n = length;
            if (type == 'F' || type == 'A')
            {
                if (!amqp_fields(value, depth + 1U, nodes, type == 'A'))
                    return false;
            }
            if (type == 'S')
            {
                if (!utf8(value))
                    return false;
                if (properties && name == "product" && text(value))
                    properties->product = value;
                if (properties && name == "version" && version(value))
                    properties->version = value;
            }
            break;
        }
        default:
            return false;
        }
        if (n > s.size() - p)
            return false;
        p += n;
    }
    return true;
}
std::optional<ProtocolIdentity> amqp(std::string_view q, std::string_view s)
{
    if (q != std::string_view{"AMQP\0\0\x09\x01", 8U})
        return std::nullopt;
    if (s.starts_with("AMQP"))
    {
        if (s.size() < 8U || !(s.substr(4U, 4U) == std::string_view{"\0\0\x09\x01", 4U} ||
                               s.substr(4U, 4U) == std::string_view{"\0\x01\0\0", 4U}))
            return std::nullopt;
        return identity("amqp", "AMQP", "amqp-header-v1");
    }
    if (s.size() < 8U || byte(s, 0U) != 1U || number(s, 1U, 2U) != 0U)
        return std::nullopt;
    const auto size = number(s, 3U, 4U);
    if (size < 12U || size > s.size() - 8U || byte(s, 7U + size) != 0xceU)
        return std::nullopt;
    const auto b = s.substr(7U, size);
    if (number(b, 0U, 2U) != 10U || number(b, 2U, 2U) != 10U || byte(b, 4U) != 0U || byte(b, 5U) != 9U)
        return std::nullopt;
    const auto table = number(b, 6U, 4U);
    if (table > b.size() - 10U)
        return std::nullopt;
    AmqpProperties properties;
    std::size_t nodes = 0U;
    if (!amqp_fields(b.substr(10U, table), 0U, nodes, false, &properties))
        return std::nullopt;
    std::size_t p = 10U + table;
    for (unsigned int i = 0U; i < 2U; ++i)
    {
        if (b.size() - p < 4U)
            return std::nullopt;
        const auto n = number(b, p, 4U);
        p += 4U;
        if (n == 0U || n > b.size() - p || !text(b.substr(p, n)))
            return std::nullopt;
        p += n;
    }
    if (p != b.size())
        return std::nullopt;
    auto out = identity("amqp", "AMQP", "amqp-connection-start-v1");
    if (properties.product == "RabbitMQ")
    {
        out.product = properties.product;
        out.version = properties.version;
        if (!out.version.empty())
            out.version_source = "server-properties.version";
    }
    return out;
}

std::optional<ProtocolIdentity> text_exchange(std::string_view f, std::string_view q, std::string_view s,
                                              bool terminal)
{
    const auto first = line(s);
    if (f == "ssh")
    {
        if (!(q.empty() || q == "\r\n" || q == "\n"))
            return std::nullopt;
        std::size_t start = 0U;
        for (unsigned int count = 0U; count < 50U && start < s.size(); ++count)
        {
            const auto row = line(s.substr(start));
            if (row.empty())
                return std::nullopt;
            if (row.starts_with("SSH-"))
            {
                if (row.size() > 253U)
                    return std::nullopt;
                const auto sep = row.find('-', 4U);
                if (sep == std::string_view::npos)
                    return std::nullopt;
                const auto proto = row.substr(4U, sep - 4U);
                if (!(proto == "2.0" || proto == "1.99"))
                    return std::nullopt;
                const auto software = row.substr(sep + 1U, row.find(' ', sep + 1U) - sep - 1U);
                if (!text(software) || software.size() > 128U)
                    return std::nullopt;
                for (char c : software)
                    if (c == ' ' || c == '-')
                    {
                        if (c == ' ')
                            return std::nullopt;
                    }
                auto out = identity(f, "SSH", "ssh-identification-v1");
                out.protocol_version = proto;
                for (auto marker : {std::pair<std::string_view, std::string_view>{"OpenSSH_", "OpenSSH"},
                                    {"dropbear_", "Dropbear-SSH"},
                                    {"libssh-", "libssh"}})
                    if (software.starts_with(marker.first))
                    {
                        const auto v = software.substr(marker.first.size());
                        if (!version(v))
                            return std::nullopt;
                        out.product = marker.second;
                        out.version = v;
                        out.version_source = "software-identification";
                    }
                if (out.product == "SSH")
                    out.product = software;
                return out;
            }
            start = s.find('\n', start) + 1U;
        }
        return std::nullopt;
    }
    if (f == "vnc")
    {
        if (!(q.empty() || q == "\r\n") || s.size() < 12U || s.substr(0U, 4U) != "RFB " || s[11U] != '\n' ||
            s[7U] != '.')
            return std::nullopt;
        for (auto i : {4U, 5U, 6U, 8U, 9U, 10U})
            if (s[i] < '0' || s[i] > '9')
                return std::nullopt;
        const auto v = s.substr(4U, 7U);
        if (!(v == "003.003" || v == "003.007" || v == "003.008" || v == "003.889"))
            return std::nullopt;
        auto out = identity(f, "RFB", "rfb-identification-v1");
        out.protocol_version = v;
        return out;
    }
    if (f == "memcached")
    {
        if (q != "version\r\n" || !first.starts_with("VERSION ") || !version(first.substr(8U)))
            return std::nullopt;
        auto out = identity(f, "Memcached", "memcached-version-v1");
        out.version = first.substr(8U);
        out.version_source = "VERSION";
        return out;
    }
    if (f == "rsync")
    {
        if (!q.empty() || !first.starts_with("@RSYNCD: "))
            return std::nullopt;
        const auto v = first.substr(9U, first.find(' ', 9U) - 9U);
        const auto dot = v.find('.');
        std::size_t a = 0U, b = 0U;
        if (dot == std::string_view::npos || !decimal(v.substr(0U, dot), a) ||
            !decimal(v.substr(dot + 1U), b))
            return std::nullopt;
        auto out = identity(f, "rsyncd", "rsync-greeting-v1");
        out.protocol_version = v;
        return out;
    }
    if (f == "ftp" || f == "smtp")
    {
        if ((f == "ftp" && q != "FEAT\r\n") || (f == "smtp" && q != "EHLO scanner.invalid\r\n") ||
            first.size() < 5U || !first.starts_with("220") || !(first[3U] == ' ' || first[3U] == '-'))
            return std::nullopt;
        std::string_view greeting = first;
        if (first[3U] == '-')
        {
            std::size_t pos = s.find('\n') + 1U;
            bool ended = false;
            while (pos < s.size())
            {
                const auto row = line(s.substr(pos));
                if (row.empty())
                    return std::nullopt;
                if (row.starts_with("220 "))
                {
                    ended = true;
                    break;
                }
                pos = s.find('\n', pos) + 1U;
            }
            if (!ended)
                return std::nullopt;
        }
        auto out =
            identity(f, f == "ftp" ? "FTP" : "SMTP", f == "ftp" ? "ftp-greeting-v1" : "smtp-greeting-v1");
        bool distinctive = false;
        for (auto marker :
             f == "ftp"
                 ? std::vector<std::pair<std::string_view, std::string_view>>{{"vsFTPd ", "vsFTPd"},
                                                                              {"ProFTPD ", "ProFTPD"},
                                                                              {"FileZilla Server ",
                                                                               "FileZilla-Server"},
                                                                              {"Microsoft FTP Service",
                                                                               "Microsoft-FTP-Service"},
                                                                              {"Pure-FTPd", "Pure-FTPd"}}
                 : std::vector<std::pair<std::string_view, std::string_view>>{
                       {"Postfix", "Postfix"},
                       {"Exim ", "Exim"},
                       {"Microsoft ESMTP MAIL Service", "Microsoft-ESMTP"},
                       {"Sendmail", "Sendmail"}})
        {
            const auto pos = greeting.find(marker.first);
            if (pos == std::string_view::npos)
                continue;
            distinctive = true;
            out.product = marker.second;
            if (marker.first.ends_with(' '))
            {
                auto v = greeting.substr(pos + marker.first.size());
                v = v.substr(0U, v.find(' '));
                if (version(v))
                {
                    out.version = v;
                    out.version_source = "greeting";
                }
            }
            break;
        }
        auto lower = std::string{greeting};
        for (auto &c : lower)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c + 32);
        if (!distinctive && lower.find(f == "ftp" ? "ftp" : "smtp") == std::string::npos)
            return std::nullopt;
        return out;
    }
    if (f == "pop3" || f == "imap")
    {
        if ((f == "pop3" && q != "CAPA\r\n") || (f == "imap" && q != "a001 CAPABILITY\r\n") ||
            !first.starts_with(f == "pop3" ? "+OK " : "* OK "))
            return std::nullopt;
        auto out = identity(f, f == "pop3" ? "POP3" : "IMAP",
                            f == "pop3" ? "pop3-capability-v1" : "imap-capability-v1");
        bool vendor = false;
        for (auto product : {"Dovecot", "Courier", "Cyrus"})
            if (first.find(product) != std::string_view::npos)
            {
                out.product = product;
                vendor = true;
                break;
            }
        if (!vendor)
        {
            if (f == "pop3" && !(s.find("\r\n+OK ") != std::string_view::npos &&
                                 s.find("\r\n.\r\n") != std::string_view::npos &&
                                 (s.find("\r\nUIDL\r\n") != std::string_view::npos ||
                                  s.find("\r\nTOP\r\n") != std::string_view::npos)))
                return std::nullopt;
            if (f == "imap" && !(s.find("\r\n* CAPABILITY IMAP4") != std::string_view::npos &&
                                 s.find("\r\na001 OK ") != std::string_view::npos && s.ends_with("\r\n")))
                return std::nullopt;
        }
        return out;
    }
    if (f == "nntp")
    {
        if (q != "CAPABILITIES\r\n")
            return std::nullopt;
        std::size_t pos = 0U;
        if (first.starts_with("200 ") || first.starts_with("201 "))
            pos = s.find('\n') + 1U;
        const auto start = line(s.substr(pos));
        if (!start.starts_with("101 "))
            return std::nullopt;
        pos = s.find('\n', pos) + 1U;
        bool complete = false;
        std::string_view protocol, implementation;
        while (pos < s.size())
        {
            const auto row = line(s.substr(pos));
            if (row.empty())
                return std::nullopt;
            if (row == ".")
            {
                complete = true;
                break;
            }
            if (row.starts_with("VERSION "))
            {
                if (!protocol.empty())
                    return std::nullopt;
                protocol = row.substr(8U);
            }
            if (row.starts_with("IMPLEMENTATION INN "))
            {
                if (!implementation.empty())
                    return std::nullopt;
                implementation = row.substr(19U);
            }
            pos = s.find('\n', pos) + 1U;
        }
        std::size_t n = 0U;
        if (!complete || !decimal(protocol, n) || n != 2U ||
            (!implementation.empty() && !version(implementation)))
            return std::nullopt;
        auto out = identity(f, implementation.empty() ? "NNTP" : "INN", "nntp-capabilities-v1");
        out.protocol_version = protocol;
        if (!implementation.empty())
        {
            out.version = implementation;
            out.version_source = "IMPLEMENTATION";
        }
        return out;
    }
    if (f == "redis")
    {
        if (q != "*1\r\n$4\r\nPING\r\n*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
            return std::nullopt;
        if (first.starts_with("-NOAUTH ") || first.starts_with("-NOPERM "))
            return identity(f, "Redis-compatible", "redis-resp-v1");
        if (first != "+PONG")
            return std::nullopt;
        auto out = identity(f, "Redis-compatible", "redis-resp-v1");
        out.provisional = !terminal;
        auto rest = s.substr(s.find('\n') + 1U);
        if (rest.empty() || !rest.starts_with('$'))
            return out;
        const auto length_line = line(rest);
        std::size_t length = 0U;
        if (length_line.empty() || !decimal(length_line.substr(1U), length))
            return out;
        rest.remove_prefix(rest.find('\n') + 1U);
        if (length > rest.size() || rest.size() - length < 2U || rest.substr(length, 2U) != "\r\n")
            return out;
        out.provisional = false;
        const auto body = rest.substr(0U, length);
        if (!body.starts_with("# Server\r\n"))
            return out;
        std::size_t pos = 0U;
        std::string_view v;
        while (pos < body.size())
        {
            const auto row = line(body.substr(pos));
            if (row.empty())
                return out;
            if (row.starts_with("redis_version:"))
            {
                if (!v.empty())
                    return out;
                v = row.substr(14U);
            }
            pos = body.find('\n', pos) + 1U;
        }
        if (version(v))
        {
            out.version = v;
            out.version_source = "INFO.redis_version";
        }
        return out;
    }
    if (f == "irc")
    {
        if (q != "NICK skanprobe\r\nUSER skan 0 * :Skan probe\r\n" || !first.starts_with(':'))
            return std::nullopt;
        const auto space = first.find(' ');
        if (space == std::string_view::npos || space == 1U ||
            first.substr(space + 1U, 14U) != "001 skanprobe ")
            return std::nullopt;
        return identity(f, "IRC", "irc-welcome-v1");
    }
    if (f == "teamspeak-query")
    {
        if (q != "help\n" || first != "TS3" ||
            !line(s.substr(s.find('\n') + 1U))
                 .starts_with("Welcome to the TeamSpeak 3 ServerQuery interface"))
            return std::nullopt;
        return identity(f, "TeamSpeak-3", "teamspeak-query-greeting-v1");
    }
    if (f == "jetdirect")
    {
        if (q != std::string_view{"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X"})
            return std::nullopt;
        if (s.starts_with("\x1b%-12345X"))
            s.remove_prefix(9U);
        if (line(s) != "@PJL INFO ID")
            return std::nullopt;
        const auto model = line(s.substr(s.find('\n') + 1U));
        if (model.size() < 3U || !model.starts_with('"') || !model.ends_with('"'))
            return std::nullopt;
        auto out = identity(f, "Printer", "pjl-info-id-v1");
        out.extra = model.substr(1U, model.size() - 2U);
        return out;
    }
    return std::nullopt;
}

bool xml_stream_open(std::string_view s)
{
    if (s.size() > kLimit)
        return false;
    if (s.starts_with("<?xml "))
    {
        const auto end = s.find("?>");
        if (end == std::string_view::npos || end > 256U)
            return false;
        const auto declaration = s.substr(0U, end + 2U);
        if (declaration.find("version='1.0'") == std::string_view::npos &&
            declaration.find("version=\"1.0\"") == std::string_view::npos)
            return false;
        s.remove_prefix(end + 2U);
    }
    while (s.starts_with(' ') || s.starts_with('\r') || s.starts_with('\n') || s.starts_with('\t'))
        s.remove_prefix(1U);
    if (!s.starts_with("<stream:stream "))
        return false;
    std::size_t pos = 15U;
    std::set<std::string_view> names;
    bool client = false, stream = false;
    unsigned int count = 0U;
    const auto whitespace = [&]
    {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\r' || s[pos] == '\n' || s[pos] == '\t'))
            ++pos;
    };
    while (pos < s.size() && ++count <= 32U)
    {
        whitespace();
        if (pos == s.size())
            return false;
        if (s[pos] == '>')
            return client && stream;
        const auto start = pos;
        while (pos < s.size() &&
               ((s[pos] >= 'a' && s[pos] <= 'z') || (s[pos] >= 'A' && s[pos] <= 'Z') ||
                (s[pos] >= '0' && s[pos] <= '9') || s[pos] == ':' || s[pos] == '_' || s[pos] == '-'))
            ++pos;
        if (pos == start || !names.insert(s.substr(start, pos - start)).second)
            return false;
        const auto name = s.substr(start, pos - start);
        whitespace();
        if (pos == s.size() || s[pos++] != '=')
            return false;
        whitespace();
        if (pos == s.size() || !(s[pos] == '\'' || s[pos] == '"'))
            return false;
        const auto quote = s[pos++];
        const auto value_start = pos;
        while (pos < s.size() && s[pos] != quote)
        {
            const auto c = byte(s, pos++);
            if (c < 32U || c == 127U || c == '<' || c == '&' || pos - value_start > 1024U)
                return false;
        }
        if (pos == s.size())
            return false;
        const auto value = s.substr(value_start, pos - value_start);
        ++pos;
        if (pos < s.size() &&
            !(s[pos] == ' ' || s[pos] == '\r' || s[pos] == '\n' || s[pos] == '\t' || s[pos] == '>'))
            return false;
        if (name == "xmlns")
            client = value == "jabber:client";
        if (name == "xmlns:stream")
            stream = value == "http://etherx.jabber.org/streams";
    }
    return false;
}
std::optional<std::string_view> header(std::string_view s, std::string_view wanted)
{
    std::optional<std::string_view> result;
    const auto end = s.find("\r\n\r\n");
    if (end == std::string_view::npos)
        return std::nullopt;
    std::size_t pos = s.find("\r\n") + 2U;
    while (pos < end)
    {
        const auto next = s.find("\r\n", pos);
        const auto row = s.substr(pos, next - pos);
        const auto colon = row.find(':');
        if (colon == std::string_view::npos)
            return std::nullopt;
        auto name = std::string{row.substr(0U, colon)};
        for (auto &c : name)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c + 32);
        if (name == wanted)
        {
            if (result)
                return std::nullopt;
            auto value = row.substr(colon + 1U);
            while (value.starts_with(' ') || value.starts_with('\t'))
                value.remove_prefix(1U);
            while (value.ends_with(' ') || value.ends_with('\t'))
                value.remove_suffix(1U);
            result = value;
        }
        pos = next + 2U;
    }
    return result;
}
std::optional<ProtocolIdentity> options_exchange(std::string_view f, std::string_view q, std::string_view s,
                                                 bool terminal, unsigned int interim_count = 0U)
{
    const bool sip = f == "sip";
    if ((sip && !q.starts_with("OPTIONS sip:localhost SIP/2.0\r\n")) ||
        (!sip && !q.starts_with("OPTIONS * RTSP/1.0\r\n")))
        return std::nullopt;
    const auto prefix = sip ? std::string_view{"SIP/2.0 "} : std::string_view{"RTSP/1.0 "};
    if (!s.starts_with(prefix))
        return std::nullopt;
    const auto seq = header(s, "cseq"), request_seq = header(q, "cseq");
    if (!seq || !request_seq || *seq != *request_seq || *seq != (sip ? "1 OPTIONS" : "1"))
        return std::nullopt;
    if (sip)
    {
        const auto call = header(s, "call-id"), requested_call = header(q, "call-id"), via = header(s, "via");
        if (!call || !requested_call || *call != *requested_call || !via ||
            !via->starts_with("SIP/2.0/TCP scanner.invalid;") ||
            via->find("branch=z9hG4bK-skan") == std::string_view::npos)
            return std::nullopt;
        const auto branch = via->find("branch=");
        if (branch == std::string_view::npos || (branch > 0U && (*via)[branch - 1U] != ';') ||
            via->substr(branch + 7U, via->find(';', branch + 7U) - branch - 7U) != "z9hG4bK-skan")
            return std::nullopt;
    }
    const auto status_line = line(s);
    if (status_line.empty() || status_line.size() > 1024U)
        return std::nullopt;
    const auto header_end = s.find("\r\n\r\n");
    if (header_end == std::string_view::npos || header_end > 4096U || s.size() < prefix.size() + 4U ||
        s[prefix.size() + 3U] != ' ' || interim_count > 8U)
        return std::nullopt;
    std::size_t status = 0U;
    if (!decimal(s.substr(prefix.size(), 3U), status) || status < 100U || status > 599U)
        return std::nullopt;
    // SIP and RTSP do not use HTTP transfer codings. RTSP without an explicit
    // length is a zero-body message even on a persistent TCP connection.
    if (header(s, "transfer-encoding"))
        return std::nullopt;
    const auto content_length = header(s, "content-length");
    std::size_t length = 0U;
    if (content_length)
    {
        if (!decimal(*content_length, length) || length > kLimit)
            return std::nullopt;
    }
    else if (sip)
        return std::nullopt;
    if (length > s.size() - header_end - 4U)
        return std::nullopt;
    const auto frame_end = header_end + 4U + length;
    std::string message{s.substr(0U, frame_end)};
    if (!content_length)
        message.insert(header_end + 2U, "Content-Length: 0\r\n");
    const std::string transformed =
        status < 200U ? "HTTP/1.1 200 Interim\r\n" + message.substr(message.find("\r\n") + 2U)
                      : "HTTP/1.1 " + message.substr(prefix.size());
    const auto http = parse_http_response(transformed, terminal);
    if (http.state != HttpParseState::Complete)
        return std::nullopt;
    if (status < 200U)
    {
        if (length || frame_end == s.size())
            return std::nullopt;
        return options_exchange(f, q, s.substr(frame_end), terminal, interim_count + 1U);
    }
    auto out = identity(f, sip ? "SIP" : "RTSP", sip ? "sip-options-v1" : "rtsp-options-v1");
    out.protocol_version = sip ? "2.0" : "1.0";
    if (!http.ambiguous_server && !http.server.empty())
    {
        const auto slash = http.server.find('/');
        const auto name = http.server.substr(0U, slash);
        if (text(name) && name.size() <= 128U && name.find(' ') == std::string_view::npos)
        {
            out.product = name;
            if (slash != std::string_view::npos && version(http.server.substr(slash + 1U)))
            {
                out.version = http.server.substr(slash + 1U);
                out.version_source = "Server";
            }
        }
    }
    return out;
}

std::optional<ProtocolIdentity> compact_exchange(std::string_view f, std::string_view q, std::string_view s)
{
    if (f == "socks5")
    {
        if (q != std::string_view{"\x05\x01\0", 3U} || s.size() != 2U || byte(s, 0U) != 5U ||
            !(byte(s, 1U) == 0U || byte(s, 1U) == 255U))
            return std::nullopt;
        auto out = identity(f, "SOCKS", "socks5-method-v1");
        out.protocol_version = "5";
        out.extra = byte(s, 1U) ? "no-acceptable-method" : "no-authentication";
        return out;
    }
    if (f == "ajp13")
    {
        if (q != std::string_view{"\x12\x34\0\x01\x0a", 5U} || s != std::string_view{"AB\0\x01\x09", 5U})
            return std::nullopt;
        auto out = identity(f, "Apache-JServ-Protocol", "ajp13-cpong-v1");
        out.protocol_version = "1.3";
        return out;
    }
    if (f == "mikrotik-api")
    {
        if (q != std::string_view{"\x06/login\0", 8U})
            return std::nullopt;
        std::size_t pos = 0U, words = 0U;
        bool have = false;
        while (pos < s.size() && ++words <= 64U)
        {
            auto n = byte(s, pos++);
            std::size_t length = n;
            if (n >= 0xf0U)
            {
                if (n != 0xf0U || s.size() - pos < 4U)
                    return std::nullopt;
                length = number(s, pos, 4U);
                pos += 4U;
            }
            else if (n >= 0xe0U)
            {
                if (s.size() - pos < 3U)
                    return std::nullopt;
                length = ((n & 15U) << 24U) | number(s, pos, 3U);
                pos += 3U;
            }
            else if (n >= 0xc0U)
            {
                if (s.size() - pos < 2U)
                    return std::nullopt;
                length = ((n & 31U) << 16U) | number(s, pos, 2U);
                pos += 2U;
            }
            else if (n >= 0x80U)
            {
                if (s.size() - pos < 1U)
                    return std::nullopt;
                length = ((n & 63U) << 8U) | byte(s, pos++);
            }
            if (!length)
                return have ? std::optional{identity(f, "MikroTik-RouterOS", "routeros-api-sentence-v1")}
                            : std::nullopt;
            if (length > s.size() - pos || length > 1024U)
                return std::nullopt;
            const auto word = s.substr(pos, length);
            pos += length;
            if (words == 1U)
            {
                if (!(word == "!done" || word == "!trap" || word == "!fatal"))
                    return std::nullopt;
                have = true;
            }
            else if (!word.starts_with('=') || !text(word))
                return std::nullopt;
        }
        return std::nullopt;
    }
    if (f == "telnet")
    {
        if (q != std::string_view{"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23", 9U})
            return std::nullopt;
        std::size_t p = 0U;
        bool have = false;
        while (p < s.size() && byte(s, p) == 255U)
        {
            if (s.size() - p < 3U)
                return std::nullopt;
            const auto command = byte(s, p + 1U);
            if (command >= 251U && command <= 254U)
            {
                p += 3U;
                have = true;
            }
            else if (command == 250U)
            {
                const auto end = s.find(std::string_view{"\xff\xf0", 2U}, p + 3U);
                if (end == std::string_view::npos)
                    return std::nullopt;
                p = end + 2U;
                have = true;
            }
            else
                return std::nullopt;
        }
        return have ? std::optional{identity(f, "Telnet", "telnet-negotiation-v1")} : std::nullopt;
    }
    return std::nullopt;
}

} // namespace

bool has_exchange_validator(std::string_view family) noexcept
{
    for (auto f : {"mysql",
                   "postgresql",
                   "mongodb",
                   "cassandra",
                   "microsoft-ds",
                   "ldap",
                   "ms-wbt-server",
                   "nfs",
                   "amqp",
                   "dns",
                   "kerberos",
                   "minecraft",
                   "nats",
                   "redis",
                   "vnc",
                   "memcached",
                   "mikrotik-api",
                   "telnet",
                   "pop3",
                   "imap",
                   "ssh",
                   "ftp",
                   "smtp",
                   "nntp",
                   "rsync",
                   "socks5",
                   "ajp13",
                   "irc",
                   "xmpp",
                   "sip",
                   "rtsp",
                   "teamspeak-query",
                   "jetdirect",
                   "teamviewer",
                   "anydesk",
                   "router-management",
                   "network-management"})
        if (family == f)
            return true;
    return false;
}
std::optional<ProtocolIdentity> validate_exchange(std::string_view f, const ServiceProbeDefinition &p,
                                                  std::string_view s, bool terminal)
{
    if (p.protocol != TransportProtocol::Tcp || s.empty() || s.size() > kLimit)
        return std::nullopt;
    const std::string_view q = p.payload;
    if (f == "mysql")
        return q.empty() ? mysql(s) : std::nullopt;
    if (f == "mongodb")
        return mongo(q, s);
    if (f == "cassandra")
        return cassandra(q, s);
    if (f == "ldap")
        return ldap(q, s);
    if (f == "ms-wbt-server")
        return rdp(q, s);
    if (f == "microsoft-ds")
        return smb(q, s);
    if (f == "nfs")
        return nfs(q, s);
    if (f == "dns")
        return dns(q, s);
    if (f == "kerberos")
        return kerberos(q, s);
    if (f == "amqp")
        return amqp(q, s);
    if (f == "nats")
        return q.empty() ? parse_nats_info(s) : std::nullopt;
    if (f == "minecraft")
        return q == std::string_view{"\x0f\0\x2f\x09localhost\x63\xdd\x01\x01\0", 18U}
                   ? parse_minecraft_status(s)
                   : std::nullopt;
    if (f == "postgresql")
    {
        if (q != std::string_view{"\0\0\0\x08\x04\xd2\x16\x2f", 8U} || !(s == "S" || s == "N"))
            return std::nullopt;
        auto out = identity(f, "PostgreSQL-compatible", "postgresql-sslresponse-v1");
        out.extra = s == "S" ? "SSL-available" : "SSL-unavailable";
        return out;
    }
    if (f == "xmpp")
        return xml_stream_open(q) && xml_stream_open(s)
                   ? std::optional{identity(f, "XMPP", "xmpp-stream-open-v1")}
                   : std::nullopt;
    if (f == "sip" || f == "rtsp")
        return options_exchange(f, q, s, terminal);
    if (auto result = compact_exchange(f, q, s))
        return result;
    return text_exchange(f, q, s, terminal);
}
} // namespace skan::detect
