#ifndef SKAN_DISCOVERY_DISCOVERY_SCHEDULER_HPP
#define SKAN_DISCOVERY_DISCOVERY_SCHEDULER_HPP

#include <cstddef>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "discovery/arp_discovery.hpp"
#include "discovery/discovery_probe.hpp"
#include "discovery/discovery_types.hpp"
#include "discovery/icmp_discovery.hpp"
#include "discovery/tcp_discovery.hpp"

namespace skan::discovery {

class DiscoveryScheduler final {
public:
    DiscoveryScheduler(
        io::IOEngine &io_engine,
        AuthorizationGate authorization,
        DiscoveryConfig config,
        DiscoveryTransport &transport);
    ~DiscoveryScheduler();

    DiscoveryScheduler(const DiscoveryScheduler &) = delete;
    DiscoveryScheduler &operator=(const DiscoveryScheduler &) = delete;

    core::StatusCode submit(const core::Target &target);
    core::StatusCode submit_host(const core::Target &target, const core::Host &host);
    core::StatusCode receive(const DiscoveryResponse &response);
    core::StatusCode run_once(int timeout_ms);
    core::StatusCode run();
    void stop() noexcept;

    bool complete() const noexcept;
    std::size_t pending_count() const noexcept;
    std::size_t duplicate_response_count() const noexcept;
    std::size_t late_response_count() const noexcept;
    HostState host_state(const std::string &address) const noexcept;
    std::vector<DiscoveryResult> results() const;

private:
    struct WorkItem final {
        core::Target target;
        core::Host host;
        ProbeType type{ProbeType::IcmpEcho};
    };

    struct PendingProbe final {
        ProbeId id{0U};
        ProbeType type{ProbeType::IcmpEcho};
        std::string target;
        const DiscoveryProbe *probe{nullptr};
        ProbeSubmission submission;
        DiscoveryTimePoint sent_at{};
        DiscoveryTimePoint deadline{};
        io::TimerId timer_id{0U};
    };

    const DiscoveryProbe *probe_for(ProbeType type) const noexcept;
    core::StatusCode submit_one(const core::Target &target, const core::Host &host, ProbeType type);
    void expire(ProbeId id) noexcept;
    void append_result(DiscoveryResult result);
    void cancel_all() noexcept;
    void pump() noexcept;

    io::IOEngine &io_engine_;
    AuthorizationGate authorization_;
    DiscoveryConfig config_;
    DiscoveryTransport &transport_;
    std::vector<std::unique_ptr<DiscoveryProbe>> probes_;
    std::unordered_map<ProbeId, PendingProbe> pending_;
    std::unordered_set<ProbeId> completed_probe_ids_;
    std::unordered_set<ProbeId> expired_probe_ids_;
    std::deque<WorkItem> work_queue_;
    std::unordered_map<std::string, std::vector<DiscoveryResult>> evidence_;
    std::vector<DiscoveryResult> results_;
    ProbeId next_probe_id_{1U};
    std::size_t duplicate_response_count_{0U};
    std::size_t late_response_count_{0U};
};

} // namespace skan::discovery

#endif // SKAN_DISCOVERY_DISCOVERY_SCHEDULER_HPP
