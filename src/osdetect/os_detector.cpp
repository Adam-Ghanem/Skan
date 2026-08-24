#include "osdetect/os_detector.hpp"

#include <utility>

namespace skan::osdetect {

OSDetector::OSDetector(
    io::IOEngine &engine,
    OSProbeTransport &transport,
    OSSchedulerConfig config,
    db::OSFingerprintDatabase database)
    : database_(std::move(database)),
      scheduler_(std::make_unique<OSScheduler>(engine, transport, database_, config))
{
}

OSDetector::~OSDetector() = default;

core::StatusCode OSDetector::submit(
    const core::Target &target,
    const std::vector<portscan::PortResult> &port_results,
    const std::vector<detect::ServiceResult> &service_results)
{
    (void)service_results;
    return scheduler_->submit(target, port_results);
}

void OSDetector::receive(const OSProbeResponse &response) noexcept
{
    scheduler_->receive(response);
}

core::StatusCode OSDetector::run() noexcept
{
    return scheduler_->run();
}

core::StatusCode OSDetector::run_once(int timeout_ms) noexcept
{
    return scheduler_->run_once(timeout_ms);
}

void OSDetector::stop() noexcept
{
    scheduler_->stop();
}

bool OSDetector::complete() const noexcept
{
    return scheduler_->complete();
}

core::StatusCode OSDetector::status() const noexcept
{
    return scheduler_->status();
}

const std::optional<OSDetectionResult> &OSDetector::result() const noexcept
{
    return scheduler_->result();
}

const db::OSFingerprintDatabase &OSDetector::database() const noexcept
{
    return database_;
}

} // namespace skan::osdetect
