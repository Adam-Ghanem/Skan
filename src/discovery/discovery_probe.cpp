#include "discovery/discovery_probe.hpp"

#include <utility>

namespace skan::discovery {

core::StatusCode RecordingTransport::submit(const ProbeSubmission &submission)
{
    submissions_.push_back(submission);
    return core::StatusCode::Ok;
}

const std::vector<ProbeSubmission> &RecordingTransport::submissions() const noexcept
{
    return submissions_;
}

void RecordingTransport::clear() noexcept
{
    submissions_.clear();
}

} // namespace skan::discovery
