#ifndef SKAN_DETECT_SERVICE_DETECTOR_HPP
#define SKAN_DETECT_SERVICE_DETECTOR_HPP

#include <memory>
#include <vector>

#include "detect/service_db.hpp"
#include "detect/service_scheduler.hpp"

namespace skan::detect {

class ServiceDetector final {
public:
    ServiceDetector(
        io::IOEngine &engine,
        ServiceTransport &transport,
        discovery::AuthorizationGate authorization,
        ServiceDetectionConfig config,
        ServiceProbeDatabase database = ServiceProbeDatabase::built_in());
    ~ServiceDetector();

    ServiceDetector(const ServiceDetector &) = delete;
    ServiceDetector &operator=(const ServiceDetector &) = delete;

    core::StatusCode submit(const std::vector<portscan::PortResult> &port_results);
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;
    void receive(const ServiceResponse &response) noexcept;

    const std::vector<ServiceResult> &results() const noexcept;
    bool complete() const noexcept;
    std::size_t pending_count() const noexcept;
    std::size_t queued_count() const noexcept;
    core::StatusCode status() const noexcept;
    const ServiceProbeDatabase &database() const noexcept;

private:
    ServiceProbeDatabase database_;
    std::unique_ptr<ServiceScheduler> scheduler_;
};

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_DETECTOR_HPP
