#include "detect/service_detector.hpp"

#include <utility>

namespace skan::detect {

ServiceDetector::ServiceDetector(
    io::IOEngine &engine,
    ServiceTransport &transport,
    discovery::AuthorizationGate authorization,
    ServiceDetectionConfig config,
    ServiceProbeDatabase database)
    : database_(std::move(database))
{
    scheduler_ = std::make_unique<ServiceScheduler>(
        engine,
        transport,
        database_,
        std::move(authorization),
        config);
}

ServiceDetector::~ServiceDetector() = default;

core::StatusCode ServiceDetector::submit(const std::vector<portscan::PortResult> &port_results)
{
    return scheduler_->submit(port_results);
}

core::StatusCode ServiceDetector::run() noexcept
{
    return scheduler_->run();
}

core::StatusCode ServiceDetector::run_once(int timeout_ms) noexcept
{
    return scheduler_->run_once(timeout_ms);
}

void ServiceDetector::receive(const ServiceResponse &response) noexcept
{
    scheduler_->receive(response);
}

const std::vector<ServiceResult> &ServiceDetector::results() const noexcept
{
    return scheduler_->results();
}

bool ServiceDetector::complete() const noexcept
{
    return scheduler_->complete();
}

std::size_t ServiceDetector::pending_count() const noexcept
{
    return scheduler_->pending_count();
}

std::size_t ServiceDetector::queued_count() const noexcept
{
    return scheduler_->queued_count();
}

core::StatusCode ServiceDetector::status() const noexcept
{
    return scheduler_->status();
}

const ServiceProbeDatabase &ServiceDetector::database() const noexcept
{
    return database_;
}

} // namespace skan::detect
