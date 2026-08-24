#ifndef SKAN_OSDETECT_OS_DETECTOR_HPP
#define SKAN_OSDETECT_OS_DETECTOR_HPP

#include <memory>
#include <optional>
#include <vector>

#include "db/os_db.hpp"
#include "detect/service_types.hpp"
#include "osdetect/os_scheduler.hpp"

namespace skan::osdetect {

class OSDetector final {
public:
    OSDetector(
        io::IOEngine &engine,
        OSProbeTransport &transport,
        OSSchedulerConfig config,
        db::OSFingerprintDatabase database = db::OSFingerprintDatabase::built_in());
    ~OSDetector();

    OSDetector(const OSDetector &) = delete;
    OSDetector &operator=(const OSDetector &) = delete;

    core::StatusCode submit(
        const core::Target &target,
        const std::vector<portscan::PortResult> &port_results,
        const std::vector<detect::ServiceResult> &service_results = {});
    void receive(const OSProbeResponse &response) noexcept;
    core::StatusCode run() noexcept;
    core::StatusCode run_once(int timeout_ms) noexcept;
    void stop() noexcept;

    bool complete() const noexcept;
    core::StatusCode status() const noexcept;
    const std::optional<OSDetectionResult> &result() const noexcept;
    const db::OSFingerprintDatabase &database() const noexcept;

private:
    db::OSFingerprintDatabase database_;
    std::unique_ptr<OSScheduler> scheduler_;
};

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_DETECTOR_HPP
