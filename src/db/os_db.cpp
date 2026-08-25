#include "db/os_db.hpp"

#include <charconv>
#include <fstream>
#include <sstream>
#include <string_view>
#include <unordered_set>

namespace skan::db {
namespace {

std::string_view trim(std::string_view value) noexcept
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
        value.remove_prefix(1U);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1U);
    }
    return value;
}

bool starts_with(std::string_view value, std::string_view prefix) noexcept
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

bool parse_integer(std::string_view text, std::int64_t &value) noexcept
{
    text = trim(text);
    if (text.empty()) {
        return false;
    }
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool parse_range(std::string_view text, std::int64_t &minimum, std::int64_t &maximum) noexcept
{
    text = trim(text);
    const std::size_t separator = text.find('-');
    if (separator == std::string_view::npos || separator == 0U || separator + 1U >= text.size()) {
        return false;
    }
    if (!parse_integer(text.substr(0U, separator), minimum) ||
        !parse_integer(text.substr(separator + 1U), maximum) || minimum < 0 || maximum < minimum) {
        return false;
    }
    return true;
}

bool parse_boolean(std::string_view text, bool &value) noexcept
{
    text = trim(text);
    if (text == "Y" || text == "YES" || text == "1") {
        value = true;
        return true;
    }
    if (text == "N" || text == "NO" || text == "0") {
        value = false;
        return true;
    }
    return false;
}

std::vector<std::string_view> split_pipe(std::string_view text)
{
    std::vector<std::string_view> result;
    std::size_t start = 0U;
    while (start <= text.size()) {
        const std::size_t separator = text.find('|', start);
        const std::size_t end = separator == std::string_view::npos ? text.size() : separator;
        result.push_back(trim(text.substr(start, end - start)));
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1U;
    }
    return result;
}

std::vector<std::string_view> split_comma(std::string_view text)
{
    std::vector<std::string_view> result;
    std::size_t start = 0U;
    while (start <= text.size()) {
        const std::size_t separator = text.find(',', start);
        const std::size_t end = separator == std::string_view::npos ? text.size() : separator;
        result.push_back(trim(text.substr(start, end - start)));
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1U;
    }
    return result;
}

bool parse_option(std::string_view text, packet::TcpOptionKind &option) noexcept
{
    text = trim(text);
    if (text == "NOP") {
        option = packet::TcpOptionKind::Nop;
        return true;
    }
    if (text == "MSS") {
        option = packet::TcpOptionKind::Mss;
        return true;
    }
    if (text == "WS" || text == "WSCALE") {
        option = packet::TcpOptionKind::WindowScale;
        return true;
    }
    if (text == "SACK") {
        option = packet::TcpOptionKind::SackPermitted;
        return true;
    }
    if (text == "TS" || text == "TIMESTAMP") {
        option = packet::TcpOptionKind::Timestamp;
        return true;
    }
    return false;
}

bool has_field(const OSFingerprint &fingerprint, FingerprintField field) noexcept
{
    for (const FingerprintSignature &signature : fingerprint.signatures) {
        if (signature.field == field) {
            return true;
        }
    }
    return false;
}

bool finalize(
    std::optional<OSFingerprint> &current,
    bool &has_class,
    std::unordered_set<std::string> &names,
    std::vector<OSFingerprint> &fingerprints)
{
    if (!current.has_value()) {
        return true;
    }
    if (!has_class || current->signatures.empty() || current->vendor.empty() || current->family.empty() ||
        !names.insert(current->name).second) {
        return false;
    }
    fingerprints.push_back(std::move(*current));
    current.reset();
    has_class = false;
    return true;
}

} // namespace

OSFingerprintDatabase OSFingerprintDatabase::parse(const std::string &text, core::StatusCode &status)
{
    OSFingerprintDatabase database;
    status = core::StatusCode::Ok;
    std::optional<OSFingerprint> current;
    bool has_class = false;
    std::unordered_set<std::string> names;
    std::istringstream input(text);
    std::string line;
    try {
        while (std::getline(input, line)) {
            std::string_view view = trim(line);
            const std::size_t comment = view.find('#');
            if (comment != std::string_view::npos) {
                view = trim(view.substr(0U, comment));
            }
            if (view.empty()) {
                continue;
            }
            if (starts_with(view, "Fingerprint ")) {
                if (!finalize(current, has_class, names, database.fingerprints_)) {
                    database.fingerprints_.clear();
                    status = core::StatusCode::ParseError;
                    return database;
                }
                const std::string_view name = trim(view.substr(11U));
                if (name.empty()) {
                    database.fingerprints_.clear();
                    status = core::StatusCode::ParseError;
                    return database;
                }
                current = OSFingerprint{};
                current->name = std::string{name};
                continue;
            }
            if (!current.has_value()) {
                database.fingerprints_.clear();
                status = core::StatusCode::ParseError;
                return database;
            }
            if (starts_with(view, "Class ")) {
                if (has_class) {
                    database.fingerprints_.clear();
                    status = core::StatusCode::ParseError;
                    return database;
                }
                const std::vector<std::string_view> values = split_pipe(view.substr(6U));
                if ((values.size() != 2U && values.size() != 3U && values.size() != 4U) || values[0].empty() ||
                    values[1].empty() || (values.size() >= 3U && values[2].empty()) ||
                    (values.size() == 4U && values[3].empty())) {
                    database.fingerprints_.clear();
                    status = core::StatusCode::ParseError;
                    return database;
                }
                current->vendor = std::string{values[0]};
                current->family = std::string{values[1]};
                current->generation = values.size() >= 3U ? std::string{values[2]} : std::string{};
                current->device_type = values.size() == 4U ? std::string{values[3]} : std::string{};
                has_class = true;
                continue;
            }
            const std::size_t equals = view.find('=');
            if (equals == std::string_view::npos || equals == 0U) {
                database.fingerprints_.clear();
                status = core::StatusCode::ParseError;
                return database;
            }
            const std::string_view key = trim(view.substr(0U, equals));
            const std::string_view value = trim(view.substr(equals + 1U));
            if (key.empty() || value.empty()) {
                database.fingerprints_.clear();
                status = core::StatusCode::ParseError;
                return database;
            }
            FingerprintSignature signature;
            bool recognized = true;
            if (key == "TTL" || key == "WINDOW" || key == "MSS" || key == "WSCALE" || key == "TCP_FLAGS" ||
                key == "ICMP_TTL" || key == "ICMP_TYPE" || key == "ICMP_CODE" || key == "UDP_PAYLOAD_LENGTH") {
                std::int64_t number = 0;
                if (!parse_integer(value, number) || number < 0) {
                    recognized = false;
                } else if (key == "TTL") {
                    signature.field = FingerprintField::Ttl;
                    signature.number = number;
                } else if (key == "WINDOW") {
                    signature.field = FingerprintField::Window;
                    signature.number = number;
                } else if (key == "MSS") {
                    signature.field = FingerprintField::Mss;
                    signature.number = number;
                } else if (key == "WSCALE") {
                    signature.field = FingerprintField::WindowScale;
                    signature.number = number;
                } else if (key == "TCP_FLAGS") {
                    signature.field = FingerprintField::TcpFlags;
                    signature.number = number;
                } else if (key == "ICMP_TTL") {
                    signature.field = FingerprintField::IcmpTtl;
                    signature.number = number;
                } else if (key == "UDP_PAYLOAD_LENGTH") {
                    signature.field = FingerprintField::UdpPayloadLength;
                    signature.number = number;
                } else if (key == "ICMP_TYPE") {
                    signature.field = FingerprintField::IcmpType;
                    signature.number = number;
                } else {
                    signature.field = FingerprintField::IcmpCode;
                    signature.number = number;
                }
            } else if (key == "DF" || key == "SACK" || key == "TIMESTAMP") {
                bool boolean = false;
                if (!parse_boolean(value, boolean)) {
                    recognized = false;
                } else if (key == "DF") {
                    signature.field = FingerprintField::DontFragment;
                    signature.boolean = boolean;
                } else if (key == "SACK") {
                    signature.field = FingerprintField::SackPermitted;
                    signature.boolean = boolean;
                } else {
                    signature.field = FingerprintField::Timestamps;
                    signature.boolean = boolean;
                }
            } else if (key == "TCP_OPTIONS") {
                signature.field = FingerprintField::TcpOptions;
                for (const std::string_view option_text : split_comma(value)) {
                    packet::TcpOptionKind option = packet::TcpOptionKind::Mss;
                    if (!parse_option(option_text, option)) {
                        recognized = false;
                        break;
                    }
                    signature.options.push_back(option);
                }
                if (signature.options.empty()) {
                    recognized = false;
                }
            } else if (key == "TTL_RANGE" || key == "WINDOW_RANGE" || key == "ICMP_TTL_RANGE" ||
                       key == "UDP_PAYLOAD_RANGE") {
                std::int64_t minimum = 0;
                std::int64_t maximum = 0;
                if (!parse_range(value, minimum, maximum)) {
                    recognized = false;
                } else if (key == "TTL_RANGE") {
                    signature.field = FingerprintField::Ttl;
                    signature.minimum = minimum;
                    signature.maximum = maximum;
                } else if (key == "WINDOW_RANGE") {
                    signature.field = FingerprintField::Window;
                    signature.minimum = minimum;
                    signature.maximum = maximum;
                } else if (key == "ICMP_TTL_RANGE") {
                    signature.field = FingerprintField::IcmpTtl;
                    signature.minimum = minimum;
                    signature.maximum = maximum;
                } else {
                    signature.field = FingerprintField::UdpPayloadLength;
                    signature.minimum = minimum;
                    signature.maximum = maximum;
                }
            } else if (key == "UDP_RESPONSE_BEHAVIOR") {
                signature.field = FingerprintField::UdpResponseBehavior;
                signature.text = std::string{value};
            } else if (key == "RESPONSE_PRESENCE") {
                bool presence = false;
                if (!parse_boolean(value, presence)) {
                    recognized = false;
                } else {
                    signature.field = FingerprintField::ResponsePresence;
                    signature.boolean = presence;
                }
            } else if (key == "ACK_BEHAVIOR") {
                signature.field = FingerprintField::AckBehavior;
                signature.text = std::string{value};
            } else if (key == "SEQUENCE_BEHAVIOR") {
                signature.field = FingerprintField::SequenceBehavior;
                signature.text = std::string{value};
            } else if (key == "RESPONSE_BEHAVIOR") {
                signature.field = FingerprintField::ResponseBehavior;
                signature.text = std::string{value};
            } else {
                recognized = false;
            }
            if (!recognized || has_field(*current, signature.field)) {
                database.fingerprints_.clear();
                status = core::StatusCode::ParseError;
                return database;
            }
            current->signatures.push_back(std::move(signature));
        }
        if (!finalize(current, has_class, names, database.fingerprints_) || database.fingerprints_.empty()) {
            database.fingerprints_.clear();
            status = core::StatusCode::ParseError;
            return database;
        }
    } catch (const std::bad_alloc &) {
        database.fingerprints_.clear();
        status = core::StatusCode::MemoryError;
    }
    return database;
}

OSFingerprintDatabase OSFingerprintDatabase::load_file(const std::string &path, core::StatusCode &status)
{
    OSFingerprintDatabase database;
    std::ifstream file(path);
    if (!file) {
        status = core::StatusCode::NotFound;
        database.status_ = status;
        return database;
    }
    std::ostringstream contents;
    contents << file.rdbuf();
    if (!file.good() && !file.eof()) {
        status = core::StatusCode::IoError;
        database.status_ = status;
        return database;
    }
    database = parse(contents.str(), status);
    database.status_ = status;
    return database;
}

OSFingerprintDatabase OSFingerprintDatabase::built_in()
{
    core::StatusCode status = core::StatusCode::InternalError;
    OSFingerprintDatabase database = load_file("data/os-fingerprints.db", status);
    database.status_ = status;
    return database;
}

core::StatusCode OSFingerprintDatabase::status() const noexcept
{
    return status_;
}

const std::vector<OSFingerprint> &OSFingerprintDatabase::fingerprints() const noexcept
{
    return fingerprints_;
}

} // namespace skan::db
