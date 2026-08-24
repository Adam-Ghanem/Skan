#include <cassert>
#include <chrono>

#include "io/io_engine.hpp"

int main()
{
    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);

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
    const auto start = skan::io::TimerClock::now();
    const skan::io::TimerId delayed_timer = engine.schedule(std::chrono::milliseconds{5}, [&delayed_called] {
        delayed_called = true;
    });
    assert(delayed_timer != 0U);
    assert(engine.run_once(50) == skan::core::StatusCode::Ok);
    assert(delayed_called);
    assert(skan::io::TimerClock::now() >= start);

    assert(engine.cancel(999999U) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    return 0;
}
