#include <algorithm>
#include <cassert>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "orchestrator/scan_pipeline.hpp"
#include "packet/udp.hpp"

namespace {

class QueuedUDPTransport final : public skan::portscan::UDPScanTransport {
public:
    struct Pending final {
        skan::portscan::UDPSubmission submission;
        skan::portscan::UDPResponseCallback callback;
    };

    explicit QueuedUDPTransport(std::shared_ptr<std::vector<Pending>> pending) : pending_(std::move(pending)) {}
    bool supports() const noexcept override { return true; }
    skan::core::StatusCode submit(const skan::portscan::UDPSubmission &submission,
                                  skan::portscan::UDPResponseCallback callback) override
    {
        pending_->push_back({submission, std::move(callback)});
        return skan::core::StatusCode::Ok;
    }
    skan::core::StatusCode cancel(skan::portscan::UDPProbeId) noexcept override
    {
        return skan::core::StatusCode::Ok;
    }
    void flush()
    {
        while (!pending_->empty()) {
            Pending item = std::move(pending_->front());
            pending_->erase(pending_->begin());
            skan::packet::UDP response_packet;
            response_packet.set_source_port(item.submission.port.number);
            response_packet.set_destination_port(item.submission.source_port);
            response_packet.set_payload({0x42U});
            std::vector<std::uint8_t> bytes(response_packet.serialized_size(), 0U);
            assert(response_packet.serialize(bytes) == skan::core::StatusCode::Ok);
            item.callback({item.submission.id, "127.0.0.1", 0x7F000001U,
                           item.submission.port.number, item.submission.source_port,
                           skan::portscan::UDPResponseKind::Datagram, std::move(bytes),
                           skan::portscan::UDPScanClock::now()});
        }
    }
private:
    std::shared_ptr<std::vector<Pending>> pending_;
};

class QueuedPortTransport final : public skan::portscan::PortScanTransport {
public:
    struct Pending final {
        skan::portscan::PortProbeId id{0U};
        skan::portscan::PortResponseCallback callback;
        std::string target;
    };

    explicit QueuedPortTransport(std::shared_ptr<std::vector<Pending>> pending)
        : pending_(std::move(pending))
    {
    }
    bool supports(skan::portscan::ScanProbeType) const noexcept override { return true; }
    skan::core::StatusCode submit(
        const skan::portscan::PortSubmission &submission,
        skan::portscan::PortResponseCallback callback) override
    {
        pending_->push_back({submission.id, std::move(callback), submission.target});
        return skan::core::StatusCode::Ok;
    }
    skan::core::StatusCode cancel(skan::portscan::PortProbeId) noexcept override { return skan::core::StatusCode::Ok; }
    void flush()
    {
        while (!pending_->empty()) {
            Pending item = std::move(pending_->front());
            pending_->erase(pending_->begin());
            item.callback({item.id, item.target, skan::portscan::PortResponseKind::Connected, 0, {},
                           skan::portscan::PortScanClock::now()});
        }
    }
private:
    std::shared_ptr<std::vector<Pending>> pending_;
};

} // namespace

int main()
{
    skan::orchestrator::ScanConfig config;
    config.targets = {{"127.0.0.1,::1", {{"127.0.0.1", std::nullopt, false}, {"::1", std::nullopt, false}}}};
    config.transport = skan::orchestrator::ScanTransport::Connect;
    config.port_method = skan::portscan::ScanProbeType::TcpConnect;
    config.ports = {80U};
    config.timeout = std::chrono::milliseconds{10};
    config.service_detection_enabled = true;
    config.os_detection_enabled = true;
    config.output_format = skan::output::OutputFormat::Json;

    auto port_pending = std::make_shared<std::vector<QueuedPortTransport::Pending>>();
    skan::orchestrator::ScanStageDependencies dependencies;
    dependencies.port_transport = [port_pending](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &) {
        return std::make_unique<QueuedPortTransport>(port_pending);
    };
    dependencies.after_port_submit = [port_pending](skan::portscan::PortScanScheduler &) {
        QueuedPortTransport transport(port_pending);
        transport.flush();
    };
    dependencies.after_service_submit = [](skan::detect::ServiceDetector &detector) {
        (void)detector.receive({1U, "127.0.0.1", skan::detect::ServiceResponseKind::Closed, 0, {}, false,
                                skan::detect::DetectionClock::now()});
    };
    std::vector<skan::orchestrator::ScanEventType> events;
    skan::orchestrator::ScanPipeline pipeline(config, [&](const skan::orchestrator::ScanEvent &event) {
        events.push_back(event.type);
    }, std::move(dependencies));
    std::ostringstream output;
    assert(pipeline.run(output) == skan::core::StatusCode::Ok);
    assert(pipeline.state() == skan::orchestrator::PipelineState::Completed);
    assert(pipeline.report().has_value());
    const auto summary = skan::output::calculate_summary(*pipeline.report());
    assert(summary.open_ports == 2U);
    assert(summary.services_detected == 0U);
    assert(summary.os_matches == 0U);
    assert(!pipeline.report()->warnings.empty());
    const auto service_started = std::find(events.begin(), events.end(), skan::orchestrator::ScanEventType::StageStarted);
    assert(service_started != events.end());
    assert(output.str().find("\"warnings\"") != std::string::npos);

    skan::orchestrator::ScanConfig udp_config;
    udp_config.targets = {{"127.0.0.1", {{"127.0.0.1", std::nullopt, false}}}};
    udp_config.transport = skan::orchestrator::ScanTransport::Offline;
    udp_config.port_scan_enabled = false;
    udp_config.udp_enabled = true;
    udp_config.udp_ports = {53U};
    udp_config.udp_timeout = std::chrono::milliseconds{10};
    udp_config.udp_retries = 0U;
    udp_config.output_format = skan::output::OutputFormat::Json;
    auto udp_pending = std::make_shared<std::vector<QueuedUDPTransport::Pending>>();
    skan::orchestrator::ScanStageDependencies udp_dependencies;
    udp_dependencies.udp_transport = [udp_pending](skan::io::IOEngine &, const skan::orchestrator::ScanConfig &) {
        return std::make_unique<QueuedUDPTransport>(udp_pending);
    };
    udp_dependencies.after_udp_submit = [udp_pending](skan::portscan::UDPScheduler &) {
        QueuedUDPTransport transport(udp_pending);
        transport.flush();
    };
    std::vector<skan::orchestrator::StageKind> udp_stages;
    skan::orchestrator::ScanPipeline udp_pipeline(udp_config,
        [&udp_stages](const skan::orchestrator::ScanEvent &event) {
            if (event.stage.has_value() && event.type == skan::orchestrator::ScanEventType::StageStarted) {
                udp_stages.push_back(*event.stage);
            }
        }, std::move(udp_dependencies));
    std::ostringstream udp_output;
    assert(udp_pipeline.run(udp_output) == skan::core::StatusCode::Ok);
    assert(udp_pipeline.report().has_value());
    const auto udp_summary = skan::output::calculate_summary(*udp_pipeline.report());
    assert(udp_summary.open_ports == 1U);
    assert(udp_pipeline.report()->hosts.front().ports.front().port.protocol == skan::portscan::Protocol::Udp);
    assert(udp_pipeline.report()->hosts.front().services.empty());
    assert(udp_stages.size() == 2U);
    assert(udp_stages[0] == skan::orchestrator::StageKind::UdpScan);
    assert(udp_stages[1] == skan::orchestrator::StageKind::Output);
    return 0;
}
