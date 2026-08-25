#ifndef SKAN_ORCHESTRATOR_SCAN_EVENTS_HPP
#define SKAN_ORCHESTRATOR_SCAN_EVENTS_HPP

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "core/types.hpp"
#include "orchestrator/scan_config.hpp"

namespace skan::orchestrator {

enum class ScanEventType : std::uint8_t {
    ScanStarted = 0,
    StageStarted,
    HostDiscovered,
    PortCompleted,
    ServiceDetected,
    OSDetectionCompleted,
    StageCompleted,
    ScanCompleted,
    ScanFailed,
    ScanCancelled
};

struct ScanEvent final {
    ScanEventType type{ScanEventType::ScanStarted};
    std::string session_id;
    std::optional<StageKind> stage;
    std::optional<core::Target> target;
    std::optional<std::uint16_t> port;
    std::string message;
    std::chrono::steady_clock::time_point timestamp{};
};

using ScanEventSink = std::function<void(const ScanEvent &)>;

const char *scan_event_type_name(ScanEventType type) noexcept;

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_EVENTS_HPP
