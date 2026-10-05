#include "detect/protocol_parsers.hpp"

#include <charconv>
#include <limits>
#include <vector>

namespace skan::detect {
namespace {
constexpr std::size_t kMaxResponse = 8192U;
constexpr std::size_t kMaxHeaders = 4096U;
constexpr std::size_t kMaxFields = 64U;

bool token(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || std::string_view{"!#$%&'*+-.^_`|~"}.find(c) != std::string_view::npos;
}

std::string_view trim(std::string_view s) noexcept
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1U);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1U);
    return s;
}

bool iequal(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0U; i < a.size(); ++i) {
        const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; };
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

bool unsigned_number(std::string_view text, std::size_t &n, int base = 10) noexcept
{
    if (text.empty()) return false;
    const auto r = std::from_chars(text.data(), text.data() + text.size(), n, base);
    return r.ec == std::errc{} && r.ptr == text.data() + text.size();
}

bool header_field(std::string_view line, std::string_view &name, std::string_view &value) noexcept
{
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0U || line.size() > 1024U) return false;
    name = line.substr(0U, colon);
    for (char c : name) if (!token(c)) return false;
    value = trim(line.substr(colon + 1U));
    for (unsigned char c : value) if ((c < 32U && c != 9U) || c == 127U) return false;
    return true;
}

bool chunk_extensions(std::string_view s) noexcept
{
    while (!s.empty()) {
        if (s.front() != ';') return false;
        s.remove_prefix(1U);
        s = trim(s);
        std::size_t n = 0U;
        while (n < s.size() && token(s[n])) ++n;
        if (n == 0U) return false;
        s.remove_prefix(n);
        s = trim(s);
        if (!s.empty() && s.front() == '=') {
            s.remove_prefix(1U);
            s = trim(s);
            if (s.empty()) return false;
            if (s.front() == '"') {
                s.remove_prefix(1U);
                bool closed = false;
                while (!s.empty()) {
                    const unsigned char c = static_cast<unsigned char>(s.front());
                    s.remove_prefix(1U);
                    if (c == '"') { closed = true; break; }
                    if (c == '\\') {
                        if (s.empty()) return false;
                        const auto escaped = static_cast<unsigned char>(s.front());
                        if ((escaped < 32U && escaped != 9U) || escaped == 127U) return false;
                        s.remove_prefix(1U);
                    } else if ((c < 32U && c != 9U) || c == 127U) return false;
                }
                if (!closed) return false;
            } else {
                n = 0U;
                while (n < s.size() && token(s[n])) ++n;
                if (n == 0U) return false;
                s.remove_prefix(n);
            }
            s = trim(s);
        }
    }
    return true;
}

HttpParseState dechunk(std::string_view encoded, std::string &body)
{
    std::size_t position = 0U;
    for (std::size_t chunks = 0U; chunks < 256U; ++chunks) {
        const auto end = encoded.find("\r\n", position);
        if (end == std::string_view::npos) return HttpParseState::Headers;
        const auto line = encoded.substr(position, end - position);
        if (line.size() > 256U) return HttpParseState::Malformed;
        const auto semi = line.find(';');
        std::size_t size = 0U;
        if (!unsigned_number(line.substr(0U, semi), size, 16) || size > kMaxResponse ||
            (semi != std::string_view::npos && !chunk_extensions(line.substr(semi)))) return HttpParseState::Malformed;
        position = end + 2U;
        if (size == 0U) {
            for (std::size_t fields = 0U; fields < kMaxFields; ++fields) {
                const auto trailer_end = encoded.find("\r\n", position);
                if (trailer_end == std::string_view::npos) return HttpParseState::Headers;
                if (trailer_end == position) return HttpParseState::Complete;
                std::string_view name, value;
                if (!header_field(encoded.substr(position, trailer_end - position), name, value) ||
                    iequal(name, "Content-Length") || iequal(name, "Transfer-Encoding") ||
                    iequal(name, "Content-Encoding") || iequal(name, "Content-Type")) return HttpParseState::Malformed;
                position = trailer_end + 2U;
            }
            return HttpParseState::Malformed;
        }
        if (size > encoded.size() - position) return HttpParseState::Headers;
        if (body.size() > kMaxResponse - size) return HttpParseState::Malformed;
        body.append(encoded.substr(position, size));
        position += size;
        if (encoded.size() - position < 2U) return HttpParseState::Headers;
        if (encoded.substr(position, 2U) != "\r\n") return HttpParseState::Malformed;
        position += 2U;
    }
    return HttpParseState::Malformed;
}

// A small strict JSON reader. It does not expose a DOM or interpret numbers;
// only direct object-member types and decoded strings are used for identity.
enum class JsonKind { Object, Array, String, Scalar };
struct JsonNode { JsonKind kind; std::size_t parent; std::string key; std::string value; };

class JsonReader final {
public:
    explicit JsonReader(std::string_view input) : input_(input) {}
    bool read(bool object_only = true)
    {
        if (input_.size() > kMaxResponse || !value(std::numeric_limits<std::size_t>::max(), {}, 0U)) return false;
        whitespace();
        return position_ == input_.size() && !nodes_.empty() && (!object_only || nodes_.front().kind == JsonKind::Object);
    }
    const JsonNode *member(std::size_t parent, std::string_view key) const noexcept
    {
        for (const auto &n : nodes_) if (n.parent == parent && n.key == key) return &n;
        return nullptr;
    }
    std::size_t index(const JsonNode *node) const noexcept { return static_cast<std::size_t>(node - nodes_.data()); }
    const std::vector<JsonNode> &nodes() const noexcept { return nodes_; }
private:
    void whitespace() noexcept
    {
        while (position_ < input_.size() && std::string_view{" \t\r\n"}.find(input_[position_]) != std::string_view::npos) ++position_;
    }
    bool consume(char c) noexcept
    {
        whitespace();
        if (position_ == input_.size() || input_[position_] != c) return false;
        ++position_;
        return true;
    }
    bool hex4(std::uint32_t &code) noexcept
    {
        if (input_.size() - position_ < 4U) return false;
        code = 0U;
        for (unsigned int i = 0U; i < 4U; ++i) {
            const char c = input_[position_++];
            unsigned int n = 0U;
            if (c >= '0' && c <= '9') n = static_cast<unsigned int>(c - '0');
            else if (c >= 'a' && c <= 'f') n = static_cast<unsigned int>(c - 'a') + 10U;
            else if (c >= 'A' && c <= 'F') n = static_cast<unsigned int>(c - 'A') + 10U;
            else return false;
            code = (code << 4U) | n;
        }
        return true;
    }
    static void utf8(std::string &out, std::uint32_t code)
    {
        if (code <= 0x7fU) out.push_back(static_cast<char>(code));
        else if (code <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (code >> 6U)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        } else if (code <= 0xffffU) {
            out.push_back(static_cast<char>(0xe0U | (code >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (code >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((code >> 12U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code & 0x3fU)));
        }
    }
    bool string(std::string &out)
    {
        if (!consume('"')) return false;
        while (position_ < input_.size()) {
            auto c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') return true;
            if (c < 32U || out.size() >= 2048U) return false;
            if (c == '\\') {
                if (position_ == input_.size()) return false;
                c = static_cast<unsigned char>(input_[position_++]);
                switch (c) {
                case '"': case '\\': case '/': out.push_back(static_cast<char>(c)); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t code = 0U;
                    if (!hex4(code)) return false;
                    if (code >= 0xd800U && code <= 0xdbffU) {
                        if (input_.substr(position_, 2U) != "\\u") return false;
                        position_ += 2U;
                        std::uint32_t low = 0U;
                        if (!hex4(low) || low < 0xdc00U || low > 0xdfffU) return false;
                        code = 0x10000U + ((code - 0xd800U) << 10U) + low - 0xdc00U;
                    } else if (code >= 0xdc00U && code <= 0xdfffU) return false;
                    utf8(out, code);
                    break;
                }
                default: return false;
                }
            } else if (c >= 128U) {
                unsigned int count = 0U;
                std::uint32_t code = 0U, minimum = 0U;
                if (c >= 0xc2U && c <= 0xdfU) { count = 1U; code = c & 0x1fU; minimum = 0x80U; }
                else if (c >= 0xe0U && c <= 0xefU) { count = 2U; code = c & 0x0fU; minimum = 0x800U; }
                else if (c >= 0xf0U && c <= 0xf4U) { count = 3U; code = c & 7U; minimum = 0x10000U; }
                else return false;
                if (input_.size() - position_ < count) return false;
                for (unsigned int i = 0U; i < count; ++i) {
                    const auto next = static_cast<unsigned char>(input_[position_++]);
                    if ((next & 0xc0U) != 0x80U) return false;
                    code = (code << 6U) | (next & 0x3fU);
                }
                if (code < minimum || code > 0x10ffffU || (code >= 0xd800U && code <= 0xdfffU)) return false;
                utf8(out, code);
            } else out.push_back(static_cast<char>(c));
            if (out.size() > 2048U) return false;
        }
        return false;
    }
    bool number() noexcept
    {
        const auto digit = [&]() { return position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9'; };
        if (position_ < input_.size() && input_[position_] == '-') ++position_;
        if (!digit()) return false;
        if (input_[position_] == '0') ++position_;
        else while (digit()) ++position_;
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            if (!digit()) return false;
            while (digit()) ++position_;
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
            if (!digit()) return false;
            while (digit()) ++position_;
        }
        return true;
    }
    bool value(std::size_t parent, std::string key, std::size_t depth)
    {
        whitespace();
        if (position_ == input_.size() || depth > 16U || nodes_.size() >= 512U) return false;
        const char c = input_[position_];
        const std::size_t id = nodes_.size();
        const auto kind = c == '{' ? JsonKind::Object : c == '[' ? JsonKind::Array : c == '"' ? JsonKind::String : JsonKind::Scalar;
        nodes_.push_back({kind, parent, std::move(key), {}});
        if (kind == JsonKind::String) return string(nodes_[id].value);
        if (kind == JsonKind::Scalar) {
            for (auto literal : {std::string_view{"true"}, std::string_view{"false"}, std::string_view{"null"}}) {
                if (input_.substr(position_, literal.size()) == literal) { nodes_[id].value = literal; position_ += literal.size(); return true; }
            }
            const auto start = position_;
            if (!number()) return false;
            nodes_[id].value = input_.substr(start, position_ - start);
            return true;
        }
        ++position_;
        const char closing = kind == JsonKind::Object ? '}' : ']';
        if (consume(closing)) return true;
        do {
            std::string child_key;
            if (kind == JsonKind::Object) {
                if (!string(child_key) || child_key.size() > 128U || member(id, child_key) != nullptr || !consume(':')) return false;
            }
            if (!value(id, std::move(child_key), depth + 1U)) return false;
        } while (consume(','));
        return consume(closing);
    }
    std::string_view input_;
    std::size_t position_{0U};
    std::vector<JsonNode> nodes_;
};

bool version_token(std::string_view s, unsigned int components = 3U) noexcept
{
    if (s.empty() || s.size() > 128U || s.front() < '0' || s.front() > '9') return false;
    std::size_t pos = 0U;
    for (unsigned int part = 0U; part < components; ++part) {
        const auto start = pos;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
        if (pos == start) return false;
        if (part + 1U < components && (pos == s.size() || s[pos++] != '.')) return false;
    }
    if (pos < s.size() && s[pos] != '-' && s[pos] != '+') return false;
    if (pos < s.size() && pos + 1U == s.size()) return false;
    for (char c : s.substr(pos)) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            c == '.' || c == '-' || c == '_' || c == '+')) return false;
    }
    return true;
}
} // namespace

HttpResponse parse_http_response(std::string_view response, bool terminal)
{
    HttpResponse out;
    if (response.size() > kMaxResponse) { out.state = HttpParseState::Malformed; return out; }
    std::size_t offset = 0U;
    for (unsigned int interim = 0U; interim < 5U; ++interim) {
        const auto boundary = response.find("\r\n\r\n", offset);
        if (boundary == std::string_view::npos) {
            if (response.size() - offset > kMaxHeaders) out.state = HttpParseState::Malformed;
            return out;
        }
        if (boundary + 4U - offset > kMaxHeaders) { out.state = HttpParseState::Malformed; return out; }
        const auto end = response.find("\r\n", offset);
        const auto status = response.substr(offset, end - offset);
        std::size_t code = 0U;
        if (status.size() < 13U || status.size() > 256U ||
            !(status.starts_with("HTTP/1.0 ") || status.starts_with("HTTP/1.1 ")) ||
            status[12U] != ' ' || !unsigned_number(status.substr(9U, 3U), code) || code < 100U || code > 599U) {
            out.state = HttpParseState::Malformed; return out;
        }
        for (unsigned char c : status) if ((c < 32U && c != 9U) || c == 127U) { out.state = HttpParseState::Malformed; return out; }
        out.protocol_version = status.substr(5U, 3U);
        out.status_code = static_cast<std::uint16_t>(code);
        out.headers = response.substr(offset, boundary + 4U - offset);
        std::optional<std::size_t> content_length;
        std::string_view transfer;
        bool have_transfer = false, have_encoding = false, have_type = false, have_server = false;
        std::size_t position = end + 2U, fields = 0U;
        while (position < boundary) {
            const auto next = response.find("\r\n", position);
            std::string_view name, value;
            if (++fields > kMaxFields || next == std::string_view::npos ||
                !header_field(response.substr(position, next - position), name, value)) { out.state = HttpParseState::Malformed; return out; }
            if (iequal(name, "Content-Length")) {
                std::size_t length = 0U;
                if (!unsigned_number(value, length) || (content_length && *content_length != length)) { out.state = HttpParseState::Malformed; return out; }
                content_length = length;
            } else if (iequal(name, "Transfer-Encoding")) {
                if (have_transfer || value.empty()) { out.state = HttpParseState::Malformed; return out; }
                transfer = value; have_transfer = true;
            } else if (iequal(name, "Server")) {
                if (have_server) out.ambiguous_server = true;
                have_server = true;
                out.server = value;
            } else if (iequal(name, "Content-Encoding")) {
                if (have_encoding) { out.state = HttpParseState::Malformed; return out; }
                out.identity_encoding = iequal(value, "identity"); have_encoding = true;
            } else if (iequal(name, "Content-Type")) {
                if (have_type) { out.state = HttpParseState::Malformed; return out; }
                out.json_content = iequal(trim(value.substr(0U, value.find(';'))), "application/json");
                have_type = true;
            }
            position = next + 2U;
        }
        if (have_transfer && content_length) { out.state = HttpParseState::Malformed; return out; }
        if (code < 200U && code != 101U) { offset = boundary + 4U; out = {}; continue; }
        out.state = HttpParseState::Headers;
        const auto bytes = response.substr(boundary + 4U);
        if (code == 101U || code == 204U || code == 304U) { out.state = HttpParseState::Complete; return out; }
        if (have_transfer) {
            if (iequal(transfer, "chunked") && out.protocol_version == "1.1") out.state = dechunk(bytes, out.body);
        } else if (content_length) {
            if (*content_length <= kMaxResponse && bytes.size() >= *content_length) {
                out.body.assign(bytes.substr(0U, *content_length)); out.state = HttpParseState::Complete;
            }
        } else if (terminal) { out.body.assign(bytes); out.state = HttpParseState::Complete; }
        if (out.state != HttpParseState::Complete || !out.identity_encoding) out.body.clear();
        return out;
    }
    out.state = HttpParseState::Malformed;
    return out;
}

std::optional<SearchIdentity> parse_search_identity(std::string_view body)
{
    JsonReader reader(body);
    if (!reader.read()) return std::nullopt;
    const auto string_member = [&](std::size_t parent, std::string_view key) -> const std::string * {
        const auto *n = reader.member(parent, key);
        return n != nullptr && n->kind == JsonKind::String ? &n->value : nullptr;
    };
    const auto *name = string_member(0U, "name");
    const auto *cluster = string_member(0U, "cluster_name");
    const auto *tagline = string_member(0U, "tagline");
    const auto *version = reader.member(0U, "version");
    if (name == nullptr || name->empty() || cluster == nullptr || cluster->empty() || tagline == nullptr ||
        version == nullptr || version->kind != JsonKind::Object) return std::nullopt;
    const auto id = reader.index(version);
    const auto *number = string_member(id, "number");
    const auto *distribution_node = reader.member(id, "distribution");
    const auto *distribution = string_member(id, "distribution");
    if (number == nullptr || !version_token(*number)) return std::nullopt;
    if (*tagline == "You Know, for Search" && distribution_node == nullptr) return SearchIdentity{"elasticsearch", "Elasticsearch", *number};
    if (*tagline == "The OpenSearch Project: https://opensearch.org/" && distribution != nullptr && *distribution == "opensearch") {
        return SearchIdentity{"opensearch", "OpenSearch", *number};
    }
    return std::nullopt;
}


namespace {
std::string_view string_member(const JsonReader &r, std::size_t parent, std::string_view key)
{
    const auto *n = r.member(parent, key);
    return n && n->kind == JsonKind::String ? std::string_view{n->value} : std::string_view{};
}
bool bool_member(const JsonReader &r, std::string_view key)
{
    const auto *n = r.member(0U, key);
    return n && n->kind == JsonKind::Scalar && (n->value == "true" || n->value == "false");
}
bool integer_member(const JsonReader &r, std::string_view key, std::size_t &out)
{
    const auto *n = r.member(0U, key);
    return n && n->kind == JsonKind::Scalar && unsigned_number(n->value, out);
}
std::optional<std::string_view> unique_header(const HttpResponse &http, std::string_view wanted)
{
    std::optional<std::string_view> result;
    std::size_t p = http.headers.find("\r\n") + 2U;
    while (p < http.headers.size()) {
        const auto end = http.headers.find("\r\n", p);
        if (end == std::string_view::npos || end == p) break;
        std::string_view name, value;
        if (!header_field(http.headers.substr(p, end-p), name, value)) return std::nullopt;
        if (iequal(name, wanted)) {
            if (result) return std::nullopt;
            result = value;
        }
        p = end+2U;
    }
    return result;
}
bool request_path(std::string_view request, std::string_view path)
{
    const auto end = request.find("\r\n");
    const auto line = request.substr(0U, end);
    return line == "GET " + std::string{path} + " HTTP/1.0" ||
           line == "GET " + std::string{path} + " HTTP/1.1";
}
}

bool has_api_validator(std::string_view family) noexcept
{
    for (auto name : {"couchdb", "clickhouse", "docker", "kubernetes", "matrix", "prometheus",
                      "grafana", "vault", "etcd", "influxdb", "consul"}) if (family == name) return true;
    return false;
}

std::optional<ProtocolIdentity> parse_api_identity(
    std::string_view family, std::string_view request, const HttpResponse &http)
{
    if (!has_api_validator(family) || http.state != HttpParseState::Complete || !http.identity_encoding) return std::nullopt;
    ProtocolIdentity out;
    out.service = family;
    out.validator = std::string{family} + "-api-v1";
    const auto success = http.status_code == 200U;
    if (family == "influxdb") {
        const auto header = unique_header(http, "X-Influxdb-Version");
        if (!request_path(request,"/ping") || !(success || http.status_code == 204U) || !header || !version_token(*header)) return std::nullopt;
        out.product = "InfluxDB"; out.version = *header; out.version_source = "X-Influxdb-Version";
        return out;
    }
    if (family == "clickhouse") {
        if (!success || !request_path(request,"/?query=SELECT%20version%28%29")) return std::nullopt;
        auto body = trim(http.body);
        if (!body.empty() && body.back() == '\n') body.remove_suffix(1U);
        if (!body.empty() && body.back() == '\r') body.remove_suffix(1U);
        if (!version_token(body) && !version_token(body,4U)) return std::nullopt;
        out.product = "ClickHouse"; out.version = body; out.version_source = "SELECT version()";
        return out;
    }
    if (!http.json_content) return std::nullopt;
    JsonReader r(http.body);
    if (!r.read(family != "consul")) return std::nullopt;
    const auto str = [&](std::string_view key) { return string_member(r,0U,key); };
    if (family == "consul") {
        const auto header = unique_header(http,"X-Consul-Default-Acl-Policy");
        if (!success || !request_path(request,"/v1/status/leader") || !header || !(*header == "allow" || *header == "deny") || r.nodes().front().kind != JsonKind::String) return std::nullopt;
        out.product = "Consul";
    } else if (family == "prometheus") {
        if (!success || !request_path(request,"/api/v1/status/buildinfo") || str("status") != "success") return std::nullopt;
        const auto *data = r.member(0U,"data");
        if (!data || data->kind != JsonKind::Object) return std::nullopt;
        const auto parent = r.index(data);
        const auto v = string_member(r,parent,"version");
        if (!version_token(v) || string_member(r,parent,"revision").empty()) return std::nullopt;
        out.product = "Prometheus"; out.version = v; out.version_source = "data.version";
    } else if (family == "grafana") {
        if (!success || !request_path(request,"/api/health") || str("database") != "ok" || str("commit").empty() || !version_token(str("version"))) return std::nullopt;
        out.product = "Grafana"; out.version = str("version"); out.version_source = "version";
    } else if (family == "vault") {
        std::size_t timestamp = 0U;
        const auto code = http.status_code;
        if (!request_path(request,"/v1/sys/health") || !(code == 200U || code == 429U || code == 472U || code == 473U || code == 474U || code == 501U || code == 503U || code == 530U) ||
            !bool_member(r,"initialized") || !bool_member(r,"sealed") || !integer_member(r,"server_time_utc",timestamp) || !version_token(str("version"))) return std::nullopt;
        out.product = "Vault-API"; out.version = str("version"); out.version_source = "version";
    } else if (family == "docker") {
        const auto api = str("ApiVersion");
        std::size_t dot = api.find('.'), major = 0U, minor = 0U;
        if (!success || !request_path(request,"/version") || !version_token(str("Version")) || dot == std::string_view::npos ||
            !unsigned_number(api.substr(0U,dot),major) || !unsigned_number(api.substr(dot+1U),minor)) return std::nullopt;
        out.product = "Docker-Engine"; out.version = str("Version"); out.version_source = "Version";
    } else if (family == "kubernetes") {
        auto v = str("gitVersion");
        if (v.starts_with('v')) v.remove_prefix(1U);
        const auto dot = v.find('.'); const auto second = v.find('.',dot == std::string_view::npos ? 0U : dot+1U);
        auto minor = str("minor"); if (minor.ends_with('+')) minor.remove_suffix(1U);
        if (!success || !request_path(request,"/version") || !version_token(v) || str("gitCommit").empty() || str("major") != v.substr(0U,dot) ||
            minor != v.substr(dot+1U,second-dot-1U)) return std::nullopt;
        out.product = "Kubernetes"; out.version = v; out.version_source = "gitVersion";
    } else if (family == "etcd") {
        if (!success || !request_path(request,"/version") || !version_token(str("etcdserver")) || !version_token(str("etcdcluster"))) return std::nullopt;
        out.product = "etcd"; out.version = str("etcdserver"); out.version_source = "etcdserver";
    } else if (family == "couchdb") {
        if (!success || !request_path(request,"/") || str("couchdb") != "Welcome" || !version_token(str("version"))) return std::nullopt;
        out.product = "Apache-CouchDB"; out.version = str("version"); out.version_source = "version";
    } else if (family == "matrix") {
        if (!request_path(request,"/_matrix/client/versions")) return std::nullopt;
        const auto *versions = r.member(0U,"versions");
        if (success && versions && versions->kind == JsonKind::Array) {
            bool have = false;
            for (const auto &n : r.nodes()) if (n.parent == r.index(versions)) {
                if (n.kind != JsonKind::String || n.value.empty() || !(n.value.starts_with('v') || n.value.starts_with('r'))) return std::nullopt;
                auto value = std::string_view{n.value}.substr(1U);
                const auto dot = value.find('.'); std::size_t a = 0U, b = 0U;
                if (n.value.starts_with('r')) {
                    if (!version_token(value)) return std::nullopt;
                } else if (dot == std::string_view::npos || !unsigned_number(value.substr(0U,dot),a) || !unsigned_number(value.substr(dot+1U),b)) return std::nullopt;
                have = true;
            }
            if (!have) return std::nullopt;
        } else if (!((http.status_code == 400U || http.status_code == 404U) && str("errcode") == "M_UNRECOGNIZED" && !str("error").empty())) return std::nullopt;
        out.product = "Matrix-Homeserver";
    } else return std::nullopt;
    return out;
}

std::optional<ProtocolIdentity> parse_nats_info(std::string_view response)
{
    if (response.size() > kMaxResponse || !response.starts_with("INFO ")) return std::nullopt;
    const auto end = response.find("\r\n");
    if (end == std::string_view::npos) return std::nullopt;
    JsonReader r(response.substr(5U,end-5U));
    std::size_t proto = 0U;
    if (!r.read() || string_member(r,0U,"server_id").empty() || !integer_member(r,"proto",proto) || proto > 1U || !version_token(string_member(r,0U,"version"))) return std::nullopt;
    ProtocolIdentity out;
    out.service = "nats"; out.product = "NATS"; out.version = string_member(r,0U,"version");
    out.validator = "nats-info-json-v1"; out.version_source = "INFO.version";
    return out;
}

std::optional<ProtocolIdentity> parse_minecraft_status(std::string_view response)
{
    if (response.size() > kMaxResponse) return std::nullopt;
    std::size_t pos = 0U;
    const auto varint = [&](std::size_t &value) {
        value = 0U;
        for (unsigned int i=0U; i<5U; ++i) {
            if (pos == response.size()) return false;
            const auto b = static_cast<unsigned char>(response[pos++]);
            if (i == 4U && (b & 0xf0U)) return false;
            value |= static_cast<std::size_t>(b & 127U) << (7U*i);
            if (!(b & 128U)) return i == 0U || (b & 127U) != 0U;
        }
        return false;
    };
    std::size_t length = 0U, packet = 0U, json = 0U;
    if (!varint(length) || length != response.size()-pos || !varint(packet) || packet != 0U || !varint(json) || json != response.size()-pos) return std::nullopt;
    JsonReader r(response.substr(pos));
    if (!r.read()) return std::nullopt;
    const auto *version = r.member(0U,"version");
    const auto *players = r.member(0U,"players");
    if (!version || version->kind != JsonKind::Object || !players || players->kind != JsonKind::Object) return std::nullopt;
    const auto v = string_member(r,r.index(version),"name");
    const auto *protocol = r.member(r.index(version),"protocol");
    std::size_t n = 0U;
    if (v.empty() || v.size()>128U || !protocol || protocol->kind != JsonKind::Scalar || !unsigned_number(protocol->value,n)) return std::nullopt;
    for (unsigned char c : v) if (c<32U || c==127U) return std::nullopt;
    ProtocolIdentity out;
    out.service="minecraft"; out.product="Minecraft-Java"; out.version=v;
    out.validator="minecraft-status-json-v1"; out.version_source="version.name";
    return out;
}

std::optional<ZooKeeperIdentity> parse_zookeeper_srvr(std::string_view response, bool terminal)
{
    if (!terminal || response.empty() || response.size() > kMaxResponse || response.back() != '\n') return std::nullopt;
    ZooKeeperIdentity out;
    bool received = false, sent = false, connections = false, outstanding = false, nodes = false, zxid = false, latency = false;
    std::size_t position = 0U, fields = 0U;
    while (position < response.size()) {
        const auto end = response.find('\n', position);
        auto line = response.substr(position, end - position);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
        for (unsigned char c : line) if (c < 32U || c == 127U) return std::nullopt;
        if (line.size() > 1024U || ++fields > kMaxFields) return std::nullopt;
        if (position == 0U) {
            constexpr std::string_view prefix = "Zookeeper version: ";
            if (!line.starts_with(prefix)) return std::nullopt;
            const auto version = line.substr(prefix.size(), line.find(',') == std::string_view::npos ? std::string_view::npos : line.find(',') - prefix.size());
            if (!version_token(version)) return std::nullopt;
            out.version = version;
        } else if (line.starts_with("Zookeeper version:")) {
            return std::nullopt;
        } else if (line.starts_with("Mode:")) {
            if (!line.starts_with("Mode: ")) return std::nullopt;
            const auto mode = line.substr(6U);
            if (!out.mode.empty() || !(mode == "leader" || mode == "follower" || mode == "standalone" || mode == "observer")) return std::nullopt;
            out.mode = mode;
        } else if (line.starts_with("Latency min/avg/max:")) {
            if (!line.starts_with("Latency min/avg/max: ")) return std::nullopt;
            if (latency) return std::nullopt;
            auto tuple = line.substr(21U);
            for (unsigned int i = 0U; i < 3U; ++i) {
                const auto slash = tuple.find('/');
                std::size_t n = 0U;
                if (!unsigned_number(tuple.substr(0U, slash), n) || ((i < 2U) != (slash != std::string_view::npos))) return std::nullopt;
                if (slash != std::string_view::npos) tuple.remove_prefix(slash + 1U);
            }
            latency = true;
        } else if (line.starts_with("Zxid:")) {
            std::size_t n = 0U;
            if (zxid || !line.starts_with("Zxid: 0x") || !unsigned_number(line.substr(8U), n, 16)) return std::nullopt;
            zxid = true;
        } else {
            for (auto field : {std::pair<std::string_view, bool *>{"Received: ", &received}, {"Sent: ", &sent},
                {"Connections: ", &connections}, {"Outstanding: ", &outstanding}, {"Node count: ", &nodes}}) {
                if (line.starts_with(field.first.substr(0U, field.first.size() - 1U))) {
                    std::size_t n = 0U;
                    if (*field.second || !line.starts_with(field.first) || !unsigned_number(line.substr(field.first.size()), n)) return std::nullopt;
                    *field.second = true;
                }
            }
        }
        position = end + 1U;
    }
    if (out.mode.empty() || !received || !sent || !connections || !outstanding || !nodes || !zxid || !latency) return std::nullopt;
    return out;
}
} // namespace skan::detect
