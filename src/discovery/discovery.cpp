#include "discovery/discovery.hpp"

#include <utility>

namespace skan::discovery {

Discovery::Discovery(
    io::IOEngine &io_engine,
    DiscoveryConfig config,
    DiscoveryTransport &transport)
    : scheduler_(io_engine, std::move(config), transport)
{
}

core::StatusCode Discovery::submit(const core::Target &target)
{
    return scheduler_.submit(target);
}

core::StatusCode Discovery::receive(const DiscoveryResponse &response)
{
    return scheduler_.receive(response);
}

core::StatusCode Discovery::run_once(int timeout_ms)
{
    return scheduler_.run_once(timeout_ms);
}

core::StatusCode Discovery::run()
{
    return scheduler_.run();
}

void Discovery::stop() noexcept
{
    scheduler_.stop();
}

bool Discovery::complete() const noexcept
{
    return scheduler_.complete();
}

std::size_t Discovery::pending_count() const noexcept
{
    return scheduler_.pending_count();
}

HostState Discovery::host_state(const std::string &address) const noexcept
{
    return scheduler_.host_state(address);
}

std::vector<DiscoveryResult> Discovery::results() const
{
    return scheduler_.results();
}

} // namespace skan::discovery
