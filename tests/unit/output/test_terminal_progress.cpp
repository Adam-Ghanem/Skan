#include <cassert>
#include <sstream>
#include <string>
#include <utility>

#include "output/terminal/progress_renderer.hpp"

namespace {

skan::orchestrator::ScanEvent event(
    skan::orchestrator::ScanEventType type,
    std::optional<skan::orchestrator::StageKind> stage = std::nullopt,
    std::string message = {})
{
    skan::orchestrator::ScanEvent value;
    value.type = type;
    value.stage = stage;
    value.message = std::move(message);
    return value;
}

} // namespace

int main()
{
    skan::output::ProgressPolicyInput policy;
    policy.standard_output = {true, 100U, true, true};
    policy.standard_error = {true, 100U, true, true};
    policy.output_format = skan::output::OutputFormat::Normal;
    assert(skan::output::progress_allowed(policy));

    auto rejected = policy;
    rejected.standard_output.interactive = false;
    assert(!skan::output::progress_allowed(rejected));
    rejected = policy;
    rejected.standard_error.interactive = false;
    assert(!skan::output::progress_allowed(rejected));
    rejected = policy;
    rejected.output_format = skan::output::OutputFormat::Json;
    assert(!skan::output::progress_allowed(rejected));
    rejected = policy;
    rejected.writes_output_file = true;
    assert(!skan::output::progress_allowed(rejected));
    rejected = policy;
    rejected.debug_logging = true;
    assert(!skan::output::progress_allowed(rejected));

    std::ostringstream disabled_output;
    skan::output::TerminalProgressRenderer disabled(disabled_output, false, false);
    disabled.handle(event(skan::orchestrator::ScanEventType::StageStarted,
                          skan::orchestrator::StageKind::PortScan,
                          "port scan started"));
    assert(disabled_output.str().empty());

    std::ostringstream output;
    skan::output::TerminalProgressRenderer renderer(output, true, false);
    renderer.handle(event(skan::orchestrator::ScanEventType::StageStarted,
                          skan::orchestrator::StageKind::PortScan,
                          std::string("port") + '\x1b' + "[31m\nscan"));
    renderer.handle(event(skan::orchestrator::ScanEventType::PortCompleted,
                          skan::orchestrator::StageKind::PortScan));
    renderer.handle(event(skan::orchestrator::ScanEventType::PortCompleted,
                          skan::orchestrator::StageKind::PortScan));
    renderer.handle(event(skan::orchestrator::ScanEventType::StageCompleted,
                          skan::orchestrator::StageKind::PortScan));
    const std::string progress = output.str();
    assert(progress.find("2 port results completed") != std::string::npos);
    assert(progress.find("ETA") == std::string::npos);
    assert(progress.find("/s") == std::string::npos);
    assert(progress.find("\x1b[31m") == std::string::npos);
    assert(progress.find('\n') == std::string::npos);

    const std::size_t before_clear = output.str().size();
    renderer.handle(event(skan::orchestrator::ScanEventType::StageStarted,
                          skan::orchestrator::StageKind::Output));
    assert(output.str().size() > before_clear);
    assert(output.str().ends_with("\r\x1b[2K"));

    return 0;
}
