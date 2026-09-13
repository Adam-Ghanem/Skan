import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


HARNESS = r'''
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "detect/service_scheduler.hpp"

namespace {

skan::portscan::PortResult open_port(const char *target, std::uint16_t port)
{
    skan::portscan::PortResult result;
    result.target = target;
    result.port = {port, skan::portscan::Protocol::Tcp};
    result.state = skan::portscan::PortState::Open;
    result.probe = skan::portscan::ScanProbeType::TcpConnect;
    return result;
}

} // namespace

int main()
{
    using namespace skan::detect;

    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::parse(
        "Probe TCP TLSClientHello rarity=1 priority=100 timeout=100 ports=443 fallback=HTTPGet\n"
        "send \"TLS\"\n"
        "softmatch type=prefix pattern=\"\\x16\\x03\" service=tls product=TLS confidence=0.9\n"
        "Probe TCP HTTPGet rarity=1 priority=95 timeout=100 ports=443\n"
        "send \"GET / HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n\"\n"
        "match type=regex pattern=\"^HTTP/([0-9.]+)[\\\\s\\\\S]*Server: ([A-Za-z0-9._-]+)/([0-9A-Za-z._-]+)\" service=http product=\"$2\" version=\"$3\" confidence=0.96\n",
        status);
    assert(status == skan::core::StatusCode::Ok);

    skan::io::IOEngine engine;
    RecordingServiceTransport transport;
    ServiceScheduler scheduler(
        engine, transport, database,
        ServiceDetectionConfig{1U, std::chrono::milliseconds{100}, 256U, 2U});

    assert(scheduler.submit({open_port("127.0.0.1", 443U)}) == skan::core::StatusCode::Ok);
    assert(transport.submissions().size() == 1U);
    assert(transport.submissions().front().probe_name == "TLSClientHello");

    const auto tls = transport.submissions().front();
    transport.deliver({tls.id, tls.target, ServiceResponseKind::SocketError, ETIMEDOUT, {}, false,
                       DetectionClock::now()});

    // A transient failure belongs to the current probe, not the entire port. The
    // scheduler must still try the explicit HTTP fallback while budget remains.
    assert(!scheduler.complete());
    assert(transport.submissions().size() == 2U);
    assert(transport.submissions().back().probe_name == "HTTPGet");

    const auto http = transport.submissions().back();
    const std::string http_response =
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.29\r\n"
        "Connection: close\r\n"
        "\r\n";
    const std::vector<std::uint8_t> http_bytes(http_response.begin(), http_response.end());
    transport.deliver({http.id, http.target, ServiceResponseKind::Data, 0, http_bytes, false,
                       DetectionClock::now()});

    assert(scheduler.complete());
    assert(scheduler.results().size() == 1U);
    assert(scheduler.results().front().state == DetectionState::Detected);
    assert(scheduler.results().front().service == "http");
    assert(scheduler.results().front().product == "Apache");
    assert(scheduler.results().front().version == "2.4.29");
    return 0;
}
'''


class ServiceSchedulerTransientFailureTest(unittest.TestCase):
    def test_transient_socket_error_advances_to_fallback_probe(self) -> None:
        subprocess.run(
            ["make", "-j2", "build/test_service_scheduler"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

        object_expr = (
            "$(DETECT_OBJECTS) $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) "
            "$(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) "
            "$(CORE_OBJECTS) $(CORE_LOG_OBJECT)"
        )
        make_eval = f"print-service-test-objects: ; @echo {object_expr}"
        objects = shlex.split(
            subprocess.check_output(
                [
                    "make",
                    "-s",
                    "--no-print-directory",
                    f"--eval={make_eval}",
                    "print-service-test-objects",
                ],
                cwd=ROOT,
                text=True,
            ).strip()
        )

        with tempfile.TemporaryDirectory(prefix="skan-service-transient-") as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "service_scheduler_transient.cpp"
            obj = tmp_path / "service_scheduler_transient.o"
            binary = tmp_path / "service_scheduler_transient"
            source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")

            subprocess.run(
                [
                    "g++",
                    "-Iinclude",
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Wshadow",
                    "-Wconversion",
                    "-Wformat=2",
                    "-O2",
                    "-c",
                    str(source),
                    "-o",
                    str(obj),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                ["g++", str(obj), *objects, "-o", str(binary)],
                cwd=ROOT,
                check=True,
            )
            subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
