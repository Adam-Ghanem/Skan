#include "portscan/udp_scan.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <new>
#include <sstream>
#include <utility>

#include "discovery/discovery_types.hpp"
#include "packet/packet.hpp"

namespace skan::portscan {
namespace {

constexpr std::size_t kMaximumPayloadBytes = 512U;
constexpr std::size_t kMaximumResponseBytes = 1U << 20U;
constexpr std::uint16_t kFirstEphemeralPort = 40000U;
constexpr std::uint16_t kLastEphemeralPort = 60000U;

std::string trim_copy(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1U);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1U);
    }
    return std::string(value);
}

bool parse_positive_size(std::string_view value, std::size_t &output) noexcept
{
    unsigned long long parsed = 0ULL;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed == 0ULL ||
        parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    output = static_cast<std::size_t>(parsed);
    return true;
}

bool parse_port(std::string_view value, std::uint16_t &output) noexcept
{
    unsigned int parsed = 0U;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed > 65535U) {
        return false;
    }
    output = static_cast<std::uint16_t>(parsed);
    return true;
}

int hexadecimal_value(char value) noexcept
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

bool decode_hex(std::string_view value, std::vector<std::uint8_t> &output) noexcept
{
    if (value.size() % 2U != 0U || value.size() / 2U > kMaximumPayloadBytes) {
        return false;
    }
    try {
        output.clear();
        output.reserve(value.size() / 2U);
        for (std::size_t index = 0U; index < value.size(); index += 2U) {
            const int high = hexadecimal_value(value[index]);
            const int low = hexadecimal_value(value[index + 1U]);
            if (high < 0 || low < 0) {
                output.clear();
                return false;
            }
            output.push_back(static_cast<std::uint8_t>((high << 4) | low));
        }
    } catch (const std::bad_alloc &) {
        output.clear();
        return false;
    }
    return true;
}

std::string built_in_database_text()
{
    return "# Skan UDP probes: name port hint max_response payload_hex\n"
           "probe DNS 53 dns 512 123401000001000000000000\n"
           "probe NTP 123 ntp 512 1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
           "probe SNMP 161 snmp 2048 301002010104067075626c6963\n"
           "probe NETBIOS 137 netbios 1024 0089000010000000000000000000000000000000000000000000000000000000\n"
           "probe TFTP 69 tftp 1024 00010000\n"
           "probe IKE 500 ike 2048 00000000000000000000000000000000\n"
           "probe DEFAULT 0 generic 512 00\n";
}

PortResult make_result(const core::Host &host, const Port &port, std::size_t retry_count,
                       const std::string &probe_name, PortState state, ScanReason reason,
                       std::optional<double> rtt_ms)
{
    PortResult result;
    result.target = host.address;
    result.port = port;
    result.state = state;
    result.probe = ScanProbeType::Udp;
    result.reason = reason;
    result.rtt_ms = rtt_ms;
    result.timestamp = UDPScanClock::now();
    result.retry_count = retry_count;
    result.probe_name = probe_name;
    return result;
}

} // namespace

bool RecordingUDPTransport::supports() const noexcept { return true; }

core::StatusCode RecordingUDPTransport::submit(const UDPSubmission &submission, UDPResponseCallback callback)
{
    if (submission.id == 0U || submission.port.protocol != Protocol::Udp || submission.port.number == 0U ||
        submission.target.empty() || !callback || callbacks_.contains(submission.id)) {
        return core::StatusCode::InvalidArgument;
    }
    try {
        submissions_.push_back(submission);
        callbacks_.emplace(submission.id, std::move(callback));
    } catch (const std::bad_alloc &) {
        if (!submissions_.empty() && submissions_.back().id == submission.id) {
            submissions_.pop_back();
        }
        callbacks_.erase(submission.id);
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode RecordingUDPTransport::cancel(UDPProbeId id) noexcept
{
    callbacks_.erase(id);
    return core::StatusCode::Ok;
}

const std::vector<UDPSubmission> &RecordingUDPTransport::submissions() const noexcept
{
    return submissions_;
}

void RecordingUDPTransport::deliver(const UDPResponse &response)
{
    const auto found = callbacks_.find(response.id);
    if (found == callbacks_.end()) {
        return;
    }
    UDPResponseCallback callback = std::move(found->second);
    callbacks_.erase(found);
    callback(response);
}

void RecordingUDPTransport::clear() noexcept
{
    submissions_.clear();
    callbacks_.clear();
}

UDPProbeDatabase UDPProbeDatabase::built_in()
{
    core::StatusCode status = core::StatusCode::InternalError;
    UDPProbeDatabase database = parse(built_in_database_text(), status);
    if (status != core::StatusCode::Ok) {
        return {};
    }
    return database;
}

UDPProbeDatabase UDPProbeDatabase::parse(std::string_view text, core::StatusCode &status)
{
    UDPProbeDatabase database;
    status = core::StatusCode::Ok;
    try {
        std::istringstream input{std::string(text)};
        std::string line;
        std::unordered_set<std::string> names;
        bool has_default = false;
        while (std::getline(input, line)) {
            const std::string trimmed = trim_copy(line);
            if (trimmed.empty() || trimmed.front() == '#') {
                continue;
            }
            std::istringstream fields(trimmed);
            std::string keyword;
            std::string name;
            std::string port_text;
            std::string hint;
            std::string response_text;
            std::string payload_text;
            std::string extra;
            if (!(fields >> keyword >> name >> port_text >> hint >> response_text >> payload_text) || (fields >> extra) ||
                keyword != "probe" || name.empty() || hint.empty()) {
                status = core::StatusCode::ParseError;
                return {};
            }
            std::uint16_t port = 0U;
            std::size_t max_response = 0U;
            if (!parse_port(port_text, port) || !parse_positive_size(response_text, max_response) ||
                max_response > kMaximumResponseBytes || !names.insert(name).second) {
                status = core::StatusCode::ParseError;
                return {};
            }
            if (port == 0U && name != "DEFAULT") {
                status = core::StatusCode::ParseError;
                return {};
            }
            std::vector<std::uint8_t> payload;
            if (!decode_hex(payload_text, payload)) {
                status = core::StatusCode::ParseError;
                return {};
            }
            if (payload.empty() || payload.size() > kMaximumPayloadBytes) {
                status = core::StatusCode::ParseError;
                return {};
            }
            if (port != 0U && database.port_index_.contains(port)) {
                status = core::StatusCode::ParseError;
                return {};
            }
            database.definitions_.push_back(UDPProbeDefinition{
                std::move(name), port, std::move(payload), max_response, std::move(hint)});
            const std::size_t index = database.definitions_.size() - 1U;
            if (port == 0U) {
                if (has_default) {
                    status = core::StatusCode::ParseError;
                    return {};
                }
                database.default_index_ = index;
                has_default = true;
            } else {
                database.port_index_.emplace(port, index);
            }
        }
        if (database.definitions_.empty() || !has_default || database.default_index_ >= database.definitions_.size() ||
            database.definitions_[database.default_index_].destination_port != 0U) {
            status = core::StatusCode::ParseError;
            return {};
        }
    } catch (const std::bad_alloc &) {
        status = core::StatusCode::MemoryError;
        return {};
    }
    return database;
}

UDPProbeDatabase UDPProbeDatabase::load_file(const std::string &path, core::StatusCode &status)
{
    std::ifstream input(path);
    if (!input.is_open()) {
        status = core::StatusCode::NotFound;
        return {};
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    if (!input.good() && !input.eof()) {
        status = core::StatusCode::IoError;
        return {};
    }
    return parse(contents.str(), status);
}

const UDPProbeDefinition *UDPProbeDatabase::for_port(std::uint16_t port) const noexcept
{
    const auto found = port_index_.find(port);
    return found == port_index_.end() ? &default_probe() : &definitions_[found->second];
}

const UDPProbeDefinition &UDPProbeDatabase::default_probe() const noexcept
{
    static const UDPProbeDefinition fallback{"DEFAULT", 0U, {0U}, 512U, "generic"};
    return definitions_.empty() || default_index_ >= definitions_.size() ? fallback : definitions_[default_index_];
}

const std::vector<UDPProbeDefinition> &UDPProbeDatabase::definitions() const noexcept
{
    return definitions_;
}

UDPScheduler::UDPScheduler(
    io::IOEngine &engine,
    UDPScanTransport &transport,
    UDPProbeDatabase database,
    PortScanConfig config)
    : engine_(engine), transport_(transport), database_(std::move(database)), config_(config)
{
    if (config_.adaptive_timing) {
        timing_ = std::make_unique<scanengine::TimingController>(config_.timing_profile);
    }
}

UDPScheduler::~UDPScheduler()
{
    for (const auto &entry : pending_) {
        (void)engine_.cancel(entry.second.timer_id);
        (void)transport_.cancel(entry.first);
        release_source_port(entry.second.submission.source_port);
    }
    pending_.clear();
    queue_.clear();
    source_ports_.fill(false);
}

core::StatusCode UDPScheduler::validate_config() const noexcept
{
    if (engine_.initialization_status() != core::StatusCode::Ok) {
        return engine_.initialization_status();
    }
    if (!transport_.supports() || config_.timeout.count() <= 0 || config_.max_outstanding == 0U ||
        (timing_ != nullptr && timing_->validate() != core::StatusCode::Ok)) {
        return !transport_.supports() ? core::StatusCode::PermissionDenied : core::StatusCode::InvalidArgument;
    }
    return core::StatusCode::Ok;
}

core::StatusCode UDPScheduler::submit(const core::Target &target, const std::vector<Port> &ports)
{
    if (submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode validation = validate_config();
    if (validation != core::StatusCode::Ok) {
        status_ = validation;
        return status_;
    }
    if (target.resolved_hosts.empty() || ports.empty()) {
        status_ = core::StatusCode::InvalidArgument;
        return status_;
    }
    for (const Port &port : ports) {
        if (port.protocol != Protocol::Udp || port.number == 0U) {
            status_ = core::StatusCode::InvalidArgument;
            return status_;
        }
    }
    submitted_ = true;
    try {
        for (const core::Host &host : target.resolved_hosts) {
            if (!discovery::parse_ipv4_address(host.address).has_value()) {
                for (const Port &port : ports) {
                    append_terminal_result(WorkItem{host, port, 0U, ""}, PortState::Unknown,
                                           ScanReason::InvalidTarget);
                }
                status_ = core::StatusCode::InvalidArgument;
                continue;
            }
            for (const Port &port : ports) {
                const UDPProbeDefinition *definition = database_.for_port(port.number);
                if (definition == nullptr) {
                    status_ = core::StatusCode::InternalError;
                    return status_;
                }
                queue_.push_back(WorkItem{host, port, 0U, definition->name});
            }
        }
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
        queue_.clear();
        return status_;
    }
    if (status_ == core::StatusCode::Ok) {
        pump();
    } else {
        queue_.clear();
    }
    stop_if_idle();
    return status_;
}

core::StatusCode UDPScheduler::submit_default(const core::Target &target)
{
    return submit(target, default_udp_ports());
}

core::StatusCode UDPScheduler::run() noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode result = engine_.run();
    if (status_ == core::StatusCode::Ok && result != core::StatusCode::Ok) {
        status_ = result;
    }
    return status_;
}

core::StatusCode UDPScheduler::run_once(int timeout_ms) noexcept
{
    if (!submitted_) {
        return core::StatusCode::InvalidArgument;
    }
    const core::StatusCode result = engine_.run_once(timeout_ms);
    if (status_ == core::StatusCode::Ok && result != core::StatusCode::Ok) {
        status_ = result;
    }
    return status_;
}

void UDPScheduler::receive(const UDPResponse &response) noexcept
{
    const auto found = pending_.find(response.id);
    if (found == pending_.end()) {
        return;
    }
    const Pending &pending = found->second;
    const auto target_ipv4 = discovery::parse_ipv4_address(pending.work.host.address);
    if (!target_ipv4.has_value() ||
        (response.source_ipv4 != 0U && response.source_ipv4 != *target_ipv4) ||
        (response.source_port != 0U && response.source_port != pending.work.port.number) ||
        (response.destination_port != 0U && response.destination_port != pending.submission.source_port)) {
        return;
    }

    PortState state = PortState::Unknown;
    ScanReason reason = ScanReason::InternalError;
    bool accepted = true;
    switch (response.kind) {
    case UDPResponseKind::Datagram: {
        const UDPProbeDefinition *definition = database_.for_port(pending.work.port.number);
        const auto datagram = packet::UDP::parse(std::span<const std::uint8_t>{response.bytes});
        if (definition == nullptr || response.bytes.size() > pending.submission.max_response_bytes ||
            response.bytes.size() > definition->max_response_bytes || !datagram.has_value() ||
            datagram->source_port() != pending.work.port.number ||
            datagram->destination_port() != pending.submission.source_port) {
            state = PortState::Error;
            reason = ScanReason::MalformedResponse;
        } else {
            state = PortState::Open;
            reason = ScanReason::UdpResponse;
        }
        break;
    }
    case UDPResponseKind::IcmpPortUnreachable:
        state = PortState::Closed;
        reason = ScanReason::IcmpPortUnreachable;
        break;
    case UDPResponseKind::IcmpAdministrativelyProhibited:
        state = PortState::Filtered;
        reason = ScanReason::IcmpAdministrativelyProhibited;
        break;
    case UDPResponseKind::IcmpNetworkUnreachable:
        state = PortState::Filtered;
        reason = ScanReason::IcmpNetworkUnreachable;
        break;
    case UDPResponseKind::Malformed:
        state = PortState::Error;
        reason = ScanReason::MalformedResponse;
        break;
    case UDPResponseKind::SocketError:
        state = PortState::Error;
        reason = ScanReason::SocketError;
        break;
    default:
        accepted = false;
        break;
    }
    if (accepted) {
        const UDPScanTimePoint completed_at = response.received_at == UDPScanTimePoint{} ? UDPScanClock::now() : response.received_at;
        complete_pending(response.id, state, reason, completed_at);
    }
}

const std::vector<PortResult> &UDPScheduler::results() const noexcept
{
    sort_results();
    return results_;
}

std::size_t UDPScheduler::queued_count() const noexcept { return queue_.size(); }
std::size_t UDPScheduler::pending_count() const noexcept { return pending_.size(); }
bool UDPScheduler::complete() const noexcept { return submitted_ && queue_.empty() && pending_.empty(); }
core::StatusCode UDPScheduler::status() const noexcept { return status_; }

const scanengine::TimingController *UDPScheduler::timing_controller() const noexcept
{
    return timing_.get();
}

bool UDPScheduler::allocate_source_port(std::uint16_t &port) noexcept
{
    constexpr std::uint32_t count = static_cast<std::uint32_t>(kLastEphemeralPort) - kFirstEphemeralPort + 1U;
    for (std::uint32_t attempt = 0U; attempt < count; ++attempt) {
        std::uint32_t candidate = static_cast<std::uint32_t>(next_source_port_);
        if (candidate < kFirstEphemeralPort || candidate > kLastEphemeralPort) {
            candidate = kFirstEphemeralPort;
        }
        next_source_port_ = static_cast<std::uint16_t>(candidate == kLastEphemeralPort ? kFirstEphemeralPort : candidate + 1U);
        const std::size_t index = static_cast<std::size_t>(candidate - kFirstEphemeralPort);
        if (!source_ports_[index]) {
            source_ports_[index] = true;
            port = static_cast<std::uint16_t>(candidate);
            return true;
        }
    }
    return false;
}

void UDPScheduler::release_source_port(std::uint16_t port) noexcept
{
    if (port >= kFirstEphemeralPort && port <= kLastEphemeralPort) {
        source_ports_[static_cast<std::size_t>(port - kFirstEphemeralPort)] = false;
    }
}

void UDPScheduler::pump() noexcept
{
    const std::size_t limit = timing_ == nullptr ? config_.max_outstanding
                                                  : timing_->parallelism_limit(config_.max_outstanding);
    while (status_ == core::StatusCode::Ok && !queue_.empty() && pending_.size() < limit) {
        WorkItem work = std::move(queue_.front());
        queue_.pop_front();
        std::uint16_t source_port = 0U;
        if (!allocate_source_port(source_port)) {
            append_terminal_result(work, PortState::Error, ScanReason::InternalError);
            status_ = core::StatusCode::ResourceExhausted;
            break;
        }
        const auto destination = discovery::parse_ipv4_address(work.host.address);
        const UDPProbeDefinition *definition = database_.for_port(work.port.number);
        if (!destination.has_value() || definition == nullptr) {
            release_source_port(source_port);
            append_terminal_result(work, PortState::Unknown, ScanReason::InvalidTarget);
            status_ = core::StatusCode::InvalidArgument;
            break;
        }
        packet::UDP udp;
        udp.set_source_port(source_port);
        udp.set_destination_port(work.port.number);
        udp.set_payload(definition->payload);
        packet::IPv4 ipv4;
        ipv4.set_protocol(17U);
        ipv4.set_source_address(0U);
        ipv4.set_destination_address(*destination);
        packet::Packet packet;
        packet.set_ipv4(ipv4);
        packet.set_udp(udp);
        std::vector<std::uint8_t> bytes = packet.serialize();
        if (bytes.empty()) {
            release_source_port(source_port);
            append_terminal_result(work, PortState::Error, ScanReason::InternalError);
            status_ = core::StatusCode::InternalError;
            break;
        }
        UDPSubmission submission;
        submission.id = next_id_++;
        submission.target = work.host.address;
        submission.port = work.port;
        submission.destination_ipv4 = *destination;
        submission.source_port = source_port;
        submission.packet = bytes;
        submission.payload = definition->payload;
        submission.probe_name = definition->name;
        submission.max_response_bytes = definition->max_response_bytes;
        Pending pending{work, std::move(submission), UDPScanClock::now(), 0U};
        io::TimerId timer_id = 0U;
        try {
            const std::chrono::milliseconds timeout = timing_ == nullptr ? config_.timeout : timing_->timeout();
            timer_id = engine_.schedule(timeout, [this, id = pending.submission.id]() { on_timeout(id); });
            if (timer_id == 0U) {
                release_source_port(source_port);
                append_terminal_result(work, PortState::Error, ScanReason::InternalError);
                status_ = core::StatusCode::InternalError;
                break;
            }
            pending.timer_id = timer_id;
            const auto inserted = pending_.emplace(pending.submission.id, std::move(pending));
            if (!inserted.second) {
                (void)engine_.cancel(timer_id);
                release_source_port(source_port);
                append_terminal_result(work, PortState::Error, ScanReason::InternalError);
                status_ = core::StatusCode::InternalError;
                break;
            }
            const core::StatusCode submit_status = transport_.submit(
                inserted.first->second.submission,
                [this](const UDPResponse &response) { receive(response); });
            if (submit_status == core::StatusCode::Ok && timing_ != nullptr) {
                timing_->on_submitted(pending_.size());
            }
            if (submit_status != core::StatusCode::Ok) {
                (void)engine_.cancel(timer_id);
                pending_.erase(inserted.first);
                release_source_port(source_port);
                append_terminal_result(work, PortState::Error,
                                       submit_status == core::StatusCode::PermissionDenied
                                           ? ScanReason::CapabilityUnavailable
                                           : ScanReason::InternalError);
                status_ = submit_status;
                break;
            }
        } catch (const std::bad_alloc &) {
            (void)transport_.cancel(pending.submission.id);
            (void)engine_.cancel(timer_id);
            pending_.erase(pending.submission.id);
            release_source_port(source_port);
            append_terminal_result(work, PortState::Error, ScanReason::InternalError);
            status_ = core::StatusCode::MemoryError;
            break;
        }
    }
    stop_if_idle();
}

void UDPScheduler::sort_results() const noexcept
{
    if (results_sorted_) {
        return;
    }
    std::sort(results_.begin(), results_.end(), [](const PortResult &left, const PortResult &right) {
        if (left.target != right.target) {
            return left.target < right.target;
        }
        if (left.port.number != right.port.number) {
            return left.port.number < right.port.number;
        }
        return left.port.protocol < right.port.protocol;
    });
    results_sorted_ = true;
}

void UDPScheduler::append_terminal_result(const WorkItem &work, PortState state, ScanReason reason,
                                          std::optional<double> rtt_ms) noexcept
{
    try {
        results_.push_back(make_result(work.host, work.port, work.retry_count, work.probe_name,
                                        state, reason, rtt_ms));
        results_sorted_ = false;
    } catch (const std::bad_alloc &) {
        status_ = core::StatusCode::MemoryError;
    }
}

void UDPScheduler::complete_pending(UDPProbeId id, PortState state, ScanReason reason,
                                     UDPScanTimePoint completed_at) noexcept
{
    const auto found = pending_.find(id);
    if (found == pending_.end()) {
        return;
    }
    Pending pending = std::move(found->second);
    (void)engine_.cancel(pending.timer_id);
    (void)transport_.cancel(id);
    release_source_port(pending.submission.source_port);
    pending_.erase(found);
    double rtt = std::chrono::duration<double, std::milli>(completed_at - pending.started_at).count();
    if (rtt < 0.0) {
        rtt = 0.0;
    }
    append_terminal_result(pending.work, state, reason, rtt);
    if (timing_ != nullptr) {
        timing_->on_response(std::chrono::milliseconds{static_cast<long long>(rtt)});
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    pump();
}

void UDPScheduler::on_timeout(UDPProbeId id) noexcept
{
    const auto found = pending_.find(id);
    if (found == pending_.end()) {
        return;
    }
    Pending pending = std::move(found->second);
    (void)transport_.cancel(id);
    release_source_port(pending.submission.source_port);
    pending_.erase(found);
    if (timing_ != nullptr) {
        timing_->on_timeout();
    }
    const std::size_t max_retries = timing_ == nullptr ? config_.retries : timing_->profile().max_retries;
    if (pending.work.retry_count < max_retries) {
        ++pending.work.retry_count;
        try {
            queue_.push_front(std::move(pending.work));
            if (timing_ != nullptr) {
                ++timing_->metrics().retry_count;
                timing_->metrics().set_parallelism(pending_.size(), pending_.size());
            }
            pump();
            return;
        } catch (const std::bad_alloc &) {
            status_ = core::StatusCode::MemoryError;
        }
    }
    if (timing_ != nullptr) {
        timing_->metrics().set_parallelism(pending_.size(), pending_.size());
    }
    append_terminal_result(pending.work, PortState::OpenOrFiltered, ScanReason::UdpTimeout);
    pump();
}

void UDPScheduler::stop_if_idle() noexcept
{
    if (submitted_ && queue_.empty() && pending_.empty()) {
        engine_.stop();
    }
}

} // namespace skan::portscan
