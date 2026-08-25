#include "orchestrator/scan_events.hpp"

namespace skan::orchestrator {

const char *scan_event_type_name(ScanEventType type) noexcept
{
    switch (type) {
    case ScanEventType::ScanStarted:
        return "scan-started";
    case ScanEventType::StageStarted:
        return "stage-started";
    case ScanEventType::HostDiscovered:
        return "host-discovered";
    case ScanEventType::PortCompleted:
        return "port-completed";
    case ScanEventType::ServiceDetected:
        return "service-detected";
    case ScanEventType::OSDetectionCompleted:
        return "os-detection-completed";
    case ScanEventType::StageCompleted:
        return "stage-completed";
    case ScanEventType::ScanCompleted:
        return "scan-completed";
    case ScanEventType::ScanFailed:
        return "scan-failed";
    case ScanEventType::ScanCancelled:
        return "scan-cancelled";
    }
    return "unknown";
}

} // namespace skan::orchestrator
