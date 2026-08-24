#ifndef SKAN_DISCOVERY_DISCOVERY_HPP
#define SKAN_DISCOVERY_DISCOVERY_HPP

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "discovery/discovery_scheduler.hpp"

namespace skan::discovery {

class Discovery final {
public:
    Discovery(
        io::IOEngine &io_engine,
        AuthorizationGate authorization,
        DiscoveryConfig config,
        DiscoveryTransport &transport);

    core::StatusCode submit(const core::Target &target);
    core::StatusCode receive(const DiscoveryResponse &response);
    core::StatusCode run_once(int timeout_ms);
    core::StatusCode run();
    void stop() noexcept;

    bool complete() const noexcept;
    std::size_t pending_count() const noexcept;
    HostState host_state(const std::string &address) const noexcept;
    std::vector<DiscoveryResult> results() const;

private:
    DiscoveryScheduler scheduler_;
};

} // namespace skan::discovery

#endif // SKAN_DISCOVERY_DISCOVERY_HPP
