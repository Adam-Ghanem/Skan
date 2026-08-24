#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <unistd.h>

#include "io/event.hpp"
#include "io/io_engine.hpp"

namespace {

void close_pair(int descriptors[2])
{
    if (descriptors[0] >= 0) {
        (void)::close(descriptors[0]);
        descriptors[0] = -1;
    }
    if (descriptors[1] >= 0) {
        (void)::close(descriptors[1]);
        descriptors[1] = -1;
    }
}

void write_byte(int file_descriptor)
{
    const std::uint8_t byte = 0x5AU;
    const ssize_t result = ::write(file_descriptor, &byte, sizeof(byte));
    assert(result == static_cast<ssize_t>(sizeof(byte)));
}

} // namespace

int main()
{
    int readable_pair[2] = {-1, -1};
    assert(::pipe(readable_pair) == 0);
    assert(skan::io::IOEngine::set_nonblocking(readable_pair[0]) == skan::core::StatusCode::Ok);
    assert(skan::io::IOEngine::set_nonblocking(readable_pair[1]) == skan::core::StatusCode::Ok);
    assert(skan::io::IOEngine::set_nonblocking(-1) == skan::core::StatusCode::InvalidArgument);

    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);

    bool readable_called = false;
    skan::core::StatusCode self_remove_status = skan::core::StatusCode::InternalError;
    skan::io::Event readable_event(
        readable_pair[0],
        skan::io::EventMask::Read,
        [&engine, &readable_called, &self_remove_status](skan::io::Event &event) {
            readable_called = true;
            assert(skan::io::has_event(event.ready_mask(), skan::io::EventMask::Read));
            std::uint8_t byte = 0U;
            assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
            self_remove_status = engine.remove(event);
        });

    assert(engine.add(readable_event) == skan::core::StatusCode::Ok);
    assert(readable_event.registered());
    readable_event.set_mask(skan::io::EventMask::Read | skan::io::EventMask::Error);
    assert(engine.modify(readable_event) == skan::core::StatusCode::Ok);
    write_byte(readable_pair[1]);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(readable_called);
    assert(self_remove_status == skan::core::StatusCode::Ok);
    assert(!readable_event.registered());

    bool writable_called = false;
    skan::io::Event writable_event(
        readable_pair[1],
        skan::io::EventMask::Write,
        [&engine, &writable_called](skan::io::Event &event) {
            writable_called = true;
            assert(skan::io::has_event(event.ready_mask(), skan::io::EventMask::Write));
            engine.stop();
        });
    assert(engine.add(writable_event) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(writable_called);
    assert(engine.remove(writable_event) == skan::core::StatusCode::Ok);

    int hangup_pair[2] = {-1, -1};
    assert(::pipe(hangup_pair) == 0);
    bool hangup_called = false;
    skan::io::Event hangup_event(
        hangup_pair[0],
        skan::io::EventMask::Read | skan::io::EventMask::Hangup,
        [&engine, &hangup_called](skan::io::Event &event) {
            hangup_called = true;
            assert(skan::io::has_event(event.ready_mask(), skan::io::EventMask::Hangup));
            assert(engine.remove(event) == skan::core::StatusCode::Ok);
        });
    assert(engine.add(hangup_event) == skan::core::StatusCode::Ok);
    assert(::close(hangup_pair[1]) == 0);
    hangup_pair[1] = -1;
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(hangup_called);
    assert(!hangup_event.registered());

    int removal_pair[2] = {-1, -1};
    assert(::pipe(removal_pair) == 0);
    bool removed_event_called = false;
    skan::io::Event removed_event(
        removal_pair[0],
        skan::io::EventMask::Read,
        [&removed_event_called](const skan::io::Event &) { removed_event_called = true; });
    skan::io::Event remover_event(
        removal_pair[1],
        skan::io::EventMask::Write,
        [&engine, &removed_event](const skan::io::Event &) {
            assert(engine.remove(removed_event) == skan::core::StatusCode::Ok);
            engine.stop();
        });
    assert(engine.add(removed_event) == skan::core::StatusCode::Ok);
    assert(engine.add(remover_event) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(!removed_event.registered());
    assert(!removed_event_called);
    assert(engine.remove(remover_event) == skan::core::StatusCode::Ok);

    close_pair(readable_pair);
    close_pair(hangup_pair);
    close_pair(removal_pair);

    bool run_timer_called = false;
    const skan::io::TimerId timer_id = engine.schedule(skan::io::TimerDuration::zero(), [&engine, &run_timer_called] {
        run_timer_called = true;
        engine.stop();
    });
    assert(timer_id != 0U);
    assert(engine.run() == skan::core::StatusCode::Ok);
    assert(run_timer_called);
    assert(!engine.running());

    return 0;
}
