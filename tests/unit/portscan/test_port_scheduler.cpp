#include <cassert>
#include <cerrno>
#include <chrono>
#include <thread>
#include <vector>

#include "io/io_engine.hpp"
#include "portscan/port_scheduler.hpp"

namespace {

skan::core::Target loopback_target()
{
    return {"local", {{"127.0.0.1", std::nullopt, true}}};
}

std::vector<skan::portscan::Port> ports_from(std::uint16_t first, std::uint16_t count)
{
    std::vector<skan::portscan::Port> ports;
    for (std::uint32_t number = first; number < static_cast<std::uint32_t>(first) + count; ++number) {
        ports.push_back({static_cast<std::uint16_t>(number), skan::portscan::Protocol::Tcp});
    }
    return ports;
}

} // namespace

int main()
{
    using namespace skan::portscan;

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{100}, 1U};
        PortScanScheduler scheduler(engine, transport, config);
        const auto ports = ports_from(1000U, 5U);
        assert(scheduler.submit(loopback_target(), ports) == skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 1U);
        assert(scheduler.queued_count() == 4U);
        assert(transport.submissions().size() == 1U);

        const PortProbeId first_id = transport.submissions().front().id;
        PortResponse first{first_id, "127.0.0.1", PortResponseKind::Connected, 0, {}, PortScanClock::now()};
        transport.deliver(first);
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == PortState::Open);
        assert(scheduler.pending_count() == 1U);
        assert(scheduler.queued_count() == 3U);

        transport.deliver(first);
        assert(scheduler.results().size() == 1U);
        const PortProbeId second_id = transport.submissions().back().id;
        PortResponse second{second_id, "127.0.0.1", PortResponseKind::ConnectionRefused, ECONNREFUSED, {},
                            PortScanClock::now()};
        transport.deliver(second);
        assert(scheduler.results().size() == 2U);
        assert(scheduler.results()[1].state == PortState::Closed);
        assert(scheduler.pending_count() == 1U);
    }

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{2}, 2U};
        assert(engine.shutdown() == skan::core::StatusCode::Ok);
        PortScanScheduler scheduler(engine, transport, config);
        assert(scheduler.submit(loopback_target(), {{2000U, Protocol::Tcp}}) == skan::core::StatusCode::InternalError);
        assert(scheduler.complete());
        assert(scheduler.pending_count() == 0U);
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().reason == ScanReason::InternalError);
    }

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{2}, 2U};
        PortScanScheduler scheduler(engine, transport, config);
        assert(scheduler.submit(loopback_target(), ports_from(2000U, 3U)) == skan::core::StatusCode::Ok);
        assert(scheduler.run() == skan::core::StatusCode::Ok);
        assert(scheduler.complete());
        assert(scheduler.results().size() == 3U);
        for (const PortResult &result : scheduler.results()) {
            assert(result.state == PortState::Filtered);
            assert(result.reason == ScanReason::Timeout);
        }
    }

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpSyn, std::chrono::milliseconds{100}, 1U};
        PortScanScheduler scheduler(engine, transport, config);
        assert(scheduler.submit(loopback_target(), {{443U, Protocol::Tcp}}) == skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 1U);
        const PortSubmission &submission = transport.submissions().front();
        PortResponse malformed{submission.id, "127.0.0.1", PortResponseKind::Packet, 0, {1U}, PortScanClock::now()};
        transport.deliver(malformed);
        assert(scheduler.pending_count() == 1U);
        assert(scheduler.results().empty());
        PortResponse wrong_source{submission.id, "127.0.0.2", PortResponseKind::Packet, 0, {}, PortScanClock::now()};
        transport.deliver(wrong_source);
        assert(scheduler.pending_count() == 1U);
        assert(scheduler.results().empty());
    }

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{100}, 4U};
        PortScanScheduler scheduler(engine, transport, config);
        const skan::core::Target targets{
            "loopbacks",
            {{"127.0.0.1", std::nullopt, true}, {"127.0.0.2", std::nullopt, true}}};
        assert(scheduler.submit(targets, ports_from(3000U, 20U)) == skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 4U);
        while (!scheduler.complete()) {
            assert(!transport.submissions().empty());
            const std::vector<PortSubmission> snapshot = transport.submissions();
            const std::size_t results_before = scheduler.results().size();
            for (auto iterator = snapshot.rbegin(); iterator != snapshot.rend(); ++iterator) {
                const PortSubmission &submission = *iterator;
                PortResponse response{submission.id, submission.target, PortResponseKind::ConnectionRefused,
                                      ECONNREFUSED, {}, PortScanClock::now()};
                transport.deliver(response);
                if (scheduler.results().size() > results_before) {
                    break;
                }
            }
            assert(scheduler.results().size() > results_before);
        }
        assert(scheduler.results().size() == 40U);
        assert(scheduler.pending_count() == 0U);
        assert(scheduler.queued_count() == 0U);
    }

    {
        skan::io::IOEngine engine;
        RecordingPortScanTransport transport;
        PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{10}, 2U};
        config.adaptive_timing = true;
        config.timing_profile.min_parallelism = 1U;
        config.timing_profile.max_parallelism = 2U;
        config.timing_profile.initial_parallelism = 2U;
        config.timing_profile.minimum_timeout = std::chrono::milliseconds{1};
        config.timing_profile.maximum_timeout = std::chrono::milliseconds{20};
        config.timing_profile.recovery_threshold = 1U;
        config.timing_profile.timeout_threshold = 1U;
        config.timing_profile.max_retries = 1U;
        PortScanScheduler scheduler(engine, transport, config);
        assert(scheduler.timing_controller() != nullptr);
        assert(scheduler.submit(loopback_target(), ports_from(4000U, 3U)) == skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 2U);
        const PortProbeId first_id = transport.submissions().front().id;
        transport.deliver(PortResponse{first_id, "127.0.0.1", PortResponseKind::Connected, 0, {}, PortScanClock::now()});
        std::size_t delivered = 1U;
        while (delivered < transport.submissions().size()) {
            const PortSubmission submission = transport.submissions()[delivered++];
            transport.deliver(PortResponse{submission.id, "127.0.0.1", PortResponseKind::ConnectionRefused,
                                          ECONNREFUSED, {}, PortScanClock::now()});
        }
        assert(scheduler.complete());
        assert(scheduler.results().size() == 3U);
        assert(scheduler.timing_controller()->rtt().sample_count() >= 1U);
    }
    return 0;
}
