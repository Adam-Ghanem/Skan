#include <cassert>
#include <cmath>
#include <limits>

#include "output/result_model.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::ScanReport empty;
    assert(empty.hosts.empty());
    assert(!empty.target_spec.has_value());
    const skan::output::ScanSummary empty_summary = skan::output::calculate_summary(empty);
    assert(empty_summary.hosts == 0U);
    assert(empty_summary.ports_scanned == 0U);
    assert(skan::output::validate_report(empty) == skan::output::OutputStatus::Ok);

    const skan::output::ScanReport report = skan::output::test::make_report();
    const skan::output::ScanSummary summary = skan::output::calculate_summary(report);
    assert(summary.hosts == 2U);
    assert(summary.hosts_up == 1U);
    assert(summary.hosts_unknown == 1U);
    assert(summary.ports_scanned == 4U);
    assert(summary.open_ports == 1U);
    assert(summary.closed_ports == 1U);
    assert(summary.filtered_ports == 1U);
    assert(summary.unreachable_ports == 1U);
    assert(summary.services_detected == 1U);
    assert(summary.os_matches == 2U);
    assert(skan::output::validate_report(report) == skan::output::OutputStatus::Ok);

    skan::output::ScanReport invalid = report;
    invalid.hosts.front().address.clear();
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.hosts.front().services.front().confidence = std::numeric_limits<double>::infinity();
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.duration_ms = -1.0;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    invalid = report;
    invalid.timing_metrics->estimated_drop_rate = 2.0;
    assert(skan::output::validate_report(invalid) == skan::output::OutputStatus::InvalidReport);
    return 0;
}
