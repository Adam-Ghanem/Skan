#include "portscan/port_probe.hpp"

#include <utility>

namespace skan::portscan {

bool RecordingPortScanTransport::supports(ScanProbeType probe) const noexcept
{
    return probe == ScanProbeType::TcpConnect || probe == ScanProbeType::TcpSyn;
}

core::StatusCode RecordingPortScanTransport::submit(
    const PortSubmission &submission,
    PortResponseCallback callback)
{
    if (submission.id == 0U || !callback) {
        return core::StatusCode::InvalidArgument;
    }
    try {
        submissions_.push_back(submission);
        try {
            const auto inserted = callbacks_.emplace(submission.id, std::move(callback));
            if (!inserted.second) {
                submissions_.pop_back();
                return core::StatusCode::InvalidArgument;
            }
        } catch (...) {
            submissions_.pop_back();
            throw;
        }
    } catch (const std::bad_alloc &) {
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode RecordingPortScanTransport::cancel(PortProbeId id) noexcept
{
    callbacks_.erase(id);
    return core::StatusCode::Ok;
}

const std::vector<PortSubmission> &RecordingPortScanTransport::submissions() const noexcept
{
    return submissions_;
}

void RecordingPortScanTransport::deliver(const PortResponse &response)
{
    const auto iterator = callbacks_.find(response.id);
    if (iterator == callbacks_.end()) {
        return;
    }
    PortResponseCallback callback = std::move(iterator->second);
    callbacks_.erase(iterator);
    callback(response);
}

void RecordingPortScanTransport::clear() noexcept
{
    callbacks_.clear();
    submissions_.clear();
}

} // namespace skan::portscan
