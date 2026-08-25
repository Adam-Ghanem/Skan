#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <unistd.h>

#include "io/event.hpp"
#include "io/io_engine.hpp"

int main()
{
    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(engine.run_once(10) == skan::core::StatusCode::Ok);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(engine.run_once(-1) == skan::core::StatusCode::Ok);

    bool negative_timeout_called = false;
    assert(engine.schedule(skan::io::TimerDuration::zero(), [&negative_timeout_called] {
        negative_timeout_called = true;
    }) != 0U);
    assert(engine.run_once(-1) == skan::core::StatusCode::Ok);
    assert(negative_timeout_called);

    bool early_called = false;
    const skan::io::TimerId early_timer = engine.schedule(std::chrono::milliseconds{100}, [&early_called] {
        early_called = true;
    });
    assert(early_timer != 0U);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(!early_called);
    assert(engine.cancel(early_timer) == skan::core::StatusCode::Ok);

    bool cancelled_called = false;
    const skan::io::TimerId cancelled_timer = engine.schedule(std::chrono::milliseconds{0}, [&cancelled_called] {
        cancelled_called = true;
    });
    assert(cancelled_timer != 0U);
    assert(engine.cancel(cancelled_timer) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(!cancelled_called);
    assert(engine.cancel(cancelled_timer) == skan::core::StatusCode::Ok);
    assert(engine.cancel(999999U) == skan::core::StatusCode::Ok);

    int same_deadline_count = 0;
    const skan::io::TimerId first_timer = engine.schedule(skan::io::TimerDuration::zero(), [&same_deadline_count] {
        ++same_deadline_count;
    });
    const skan::io::TimerId second_timer = engine.schedule(skan::io::TimerDuration::zero(), [&same_deadline_count] {
        ++same_deadline_count;
    });
    assert(first_timer != 0U);
    assert(second_timer != 0U);
    assert(first_timer != second_timer);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(same_deadline_count == 2);

    bool delayed_called = false;
    const skan::io::TimerId delayed_timer = engine.schedule(std::chrono::milliseconds{5}, [&delayed_called] {
        delayed_called = true;
    });
    assert(delayed_timer != 0U);
    const auto delayed_start = skan::io::TimerClock::now();
    assert(engine.run_once(50) == skan::core::StatusCode::Ok);
    const auto delayed_elapsed = skan::io::TimerClock::now() - delayed_start;
    assert(delayed_called);
    assert(delayed_elapsed < std::chrono::milliseconds{500});

    bool chained_called = false;
    bool first_chain_called = false;
    const skan::io::TimerId chain_timer = engine.schedule(skan::io::TimerDuration::zero(), [&engine, &chained_called, &first_chain_called] {
        first_chain_called = true;
        assert(engine.schedule(skan::io::TimerDuration::zero(), [&chained_called] {
            chained_called = true;
        }) != 0U);
    });
    assert(chain_timer != 0U);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(first_chain_called);
    assert(chained_called);

    bool timer_to_stop_called = false;
    const skan::io::TimerId stop_timer = engine.schedule(skan::io::TimerDuration::zero(), [&engine, &timer_to_stop_called] {
        timer_to_stop_called = true;
        engine.stop();
    });
    assert(stop_timer != 0U);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(timer_to_stop_called);

    bool timer_to_cancel_called = false;
    const skan::io::TimerId timer_to_cancel = engine.schedule(std::chrono::milliseconds{100}, [&timer_to_cancel_called] {
        timer_to_cancel_called = true;
    });
    const skan::io::TimerId cancelling_timer = engine.schedule(skan::io::TimerDuration::zero(), [&engine, timer_to_cancel] {
        assert(engine.cancel(timer_to_cancel) == skan::core::StatusCode::Ok);
    });
    assert(timer_to_cancel != 0U);
    assert(cancelling_timer != 0U);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(!timer_to_cancel_called);

    int many_timer_count = 0;
    std::vector<skan::io::TimerId> many_timer_ids;
    many_timer_ids.reserve(10000U);
    for (int index = 0; index < 10000; ++index) {
        const skan::io::TimerId timer_id = engine.schedule(skan::io::TimerDuration::zero(), [&many_timer_count] {
            ++many_timer_count;
        });
        assert(timer_id != 0U);
        many_timer_ids.push_back(timer_id);
    }
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(many_timer_count == 10000);

    int integration_pair[2] = {-1, -1};
    assert(::pipe(integration_pair) == 0);
    bool integration_fd_called = false;
    bool integration_timer_called = false;
    skan::io::Event integration_event(
        integration_pair[0],
        skan::io::EventMask::Read,
        [&engine, &integration_fd_called](skan::io::Event &event) {
            integration_fd_called = true;
            std::uint8_t byte = 0U;
            assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
            assert(engine.remove(event) == skan::core::StatusCode::Ok);
        });
    assert(engine.add(integration_event) == skan::core::StatusCode::Ok);
    assert(engine.schedule(skan::io::TimerDuration::zero(), [&integration_timer_called] {
        integration_timer_called = true;
    }) != 0U);
    const std::uint8_t integration_byte = 0xA5U;
    assert(::write(integration_pair[1], &integration_byte, sizeof(integration_byte)) == static_cast<ssize_t>(sizeof(integration_byte)));
    assert(engine.run_once(5000) == skan::core::StatusCode::Ok);
    assert(integration_fd_called);
    assert(integration_timer_called);
    assert(::close(integration_pair[0]) == 0);
    assert(::close(integration_pair[1]) == 0);

    assert(engine.shutdown() == skan::core::StatusCode::Ok);
    assert(engine.shutdown() == skan::core::StatusCode::Ok);
    assert(engine.schedule(skan::io::TimerDuration::zero(), [] {}) == 0U);
    return 0;
}
