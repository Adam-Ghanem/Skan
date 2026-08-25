#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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
    const int read_flags = ::fcntl(readable_pair[0], F_GETFL, 0);
    const int write_flags = ::fcntl(readable_pair[1], F_GETFL, 0);
    assert(read_flags >= 0 && (read_flags & O_NONBLOCK) != 0);
    assert(write_flags >= 0 && (write_flags & O_NONBLOCK) != 0);
    assert(skan::io::IOEngine::set_nonblocking(-1) == skan::core::StatusCode::InvalidArgument);

    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(engine.run_once(10) == skan::core::StatusCode::Ok);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(engine.run_once(-1) == skan::core::StatusCode::Ok);

    skan::io::Event invalid_event(-1, skan::io::EventMask::Read, [](skan::io::Event &) {});
    assert(engine.add(invalid_event) == skan::core::StatusCode::InvalidArgument);
    assert(engine.modify(invalid_event) == skan::core::StatusCode::InvalidArgument);
    assert(engine.remove(invalid_event) == skan::core::StatusCode::NotFound);

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
    assert(engine.add(readable_event) == skan::core::StatusCode::InvalidArgument);
    assert(readable_event.registered());
    assert(engine.modify(invalid_event) == skan::core::StatusCode::InvalidArgument);
    readable_event.set_mask(skan::io::EventMask::Read | skan::io::EventMask::Error);
    assert(engine.modify(readable_event) == skan::core::StatusCode::Ok);
    write_byte(readable_pair[1]);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(readable_called);
    assert(self_remove_status == skan::core::StatusCode::Ok);
    assert(!readable_event.registered());
    assert(engine.remove(readable_event) == skan::core::StatusCode::NotFound);

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

    int callback_pair[2] = {-1, -1};
    int added_pair[2] = {-1, -1};
    assert(::pipe(callback_pair) == 0);
    assert(::pipe(added_pair) == 0);
    bool added_called = false;
    skan::io::Event added_event(
        added_pair[0],
        skan::io::EventMask::Read,
        [&engine, &added_called](skan::io::Event &event) {
            added_called = true;
            std::uint8_t byte = 0U;
            assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
            assert(engine.remove(event) == skan::core::StatusCode::Ok);
        });
    bool registrar_called = false;
    skan::io::Event registrar_event(
        callback_pair[1],
        skan::io::EventMask::Write,
        [&engine, &added_event, &registrar_called, &added_pair](skan::io::Event &) {
            registrar_called = true;
            assert(engine.add(added_event) == skan::core::StatusCode::Ok);
            write_byte(added_pair[1]);
        });
    assert(engine.add(registrar_event) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(registrar_called);
    assert(!added_called);
    assert(engine.remove(registrar_event) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(added_called);
    assert(!added_event.registered());

    int cross_removal_pair[2] = {-1, -1};
    assert(::pipe(cross_removal_pair) == 0);
    bool removed_before_dispatch_called = false;
    skan::io::Event event_removed_by_callback(
        cross_removal_pair[0],
        skan::io::EventMask::Read,
        [&removed_before_dispatch_called](skan::io::Event &) { removed_before_dispatch_called = true; });
    skan::io::Event cross_remover_event(
        cross_removal_pair[1],
        skan::io::EventMask::Write,
        [&engine, &event_removed_by_callback](skan::io::Event &) {
            assert(engine.remove(event_removed_by_callback) == skan::core::StatusCode::Ok);
            engine.stop();
        });
    assert(engine.add(event_removed_by_callback) == skan::core::StatusCode::Ok);
    assert(engine.add(cross_remover_event) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(!removed_before_dispatch_called);
    assert(!event_removed_by_callback.registered());
    assert(engine.remove(cross_remover_event) == skan::core::StatusCode::Ok);
    close_pair(cross_removal_pair);

    int stale_target_pair[2] = {-1, -1};
    int stale_remover_pair[2] = {-1, -1};
    assert(::pipe(stale_target_pair) == 0);
    assert(::pipe(stale_remover_pair) == 0);
    bool stale_target_called = false;
    auto stale_target_event = std::make_unique<skan::io::Event>(
        stale_target_pair[0], skan::io::EventMask::Read,
        [&stale_target_called](skan::io::Event &event) {
            std::uint8_t byte = 0U;
            assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
            stale_target_called = true;
        });
    bool stale_remover_called = false;
    skan::io::Event stale_remover_event(
        stale_remover_pair[1], skan::io::EventMask::Write,
        [&engine, &stale_remover_called, &stale_target_event](skan::io::Event &) {
            stale_remover_called = true;
            assert(engine.remove(*stale_target_event) == skan::core::StatusCode::Ok);
            stale_target_event.reset();
            engine.stop();
        });
    assert(engine.add(stale_remover_event) == skan::core::StatusCode::Ok);
    assert(engine.add(*stale_target_event) == skan::core::StatusCode::Ok);
    write_byte(stale_target_pair[1]);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(stale_remover_called);
    assert(stale_target_event == nullptr);
    assert(engine.remove(stale_remover_event) == skan::core::StatusCode::Ok);
    close_pair(stale_target_pair);
    close_pair(stale_remover_pair);

    int modify_pair[2] = {-1, -1};
    assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, modify_pair) == 0);
    bool modify_called = false;
    int modify_count = 0;
    skan::io::Event modify_event(
        modify_pair[0],
        skan::io::EventMask::Read,
        [&engine, &modify_called, &modify_count](skan::io::Event &event) {
            ++modify_count;
            if (modify_count == 1) {
                std::uint8_t byte = 0U;
                assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
                event.set_mask(skan::io::EventMask::Read | skan::io::EventMask::Write);
                assert(engine.modify(event) == skan::core::StatusCode::Ok);
            } else {
                modify_called = true;
                assert(skan::io::has_event(event.ready_mask(), skan::io::EventMask::Write));
                assert(engine.remove(event) == skan::core::StatusCode::Ok);
            }
        });
    assert(engine.add(modify_event) == skan::core::StatusCode::Ok);
    write_byte(modify_pair[1]);
    assert(engine.run_once(100) == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(modify_called);
    assert(!modify_event.registered());

    int run_pair[2] = {-1, -1};
    assert(::pipe(run_pair) == 0);
    bool run_called = false;
    skan::io::Event run_event(
        run_pair[0],
        skan::io::EventMask::Read,
        [&engine, &run_called](skan::io::Event &event) {
            run_called = true;
            std::uint8_t byte = 0U;
            assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
            engine.stop();
        });
    assert(engine.add(run_event) == skan::core::StatusCode::Ok);
    write_byte(run_pair[1]);
    assert(engine.run() == skan::core::StatusCode::Ok);
    assert(run_called);
    assert(!engine.running());
    assert(engine.remove(run_event) == skan::core::StatusCode::Ok);

    std::vector<std::array<int, 2>> stress_pairs;
    std::vector<std::unique_ptr<skan::io::Event>> stress_events;
    int stress_called = 0;
    stress_pairs.reserve(100U);
    for (int index = 0; index < 100; ++index) {
        stress_pairs.emplace_back(std::array<int, 2>{-1, -1});
        std::array<int, 2> &pair = stress_pairs.back();
        assert(::pipe(pair.data()) == 0);
        assert(engine.add(*stress_events.emplace_back(std::make_unique<skan::io::Event>(
            pair[0], skan::io::EventMask::Read,
            [&stress_called](skan::io::Event &event) {
                std::uint8_t byte = 0U;
                assert(::read(event.file_descriptor(), &byte, sizeof(byte)) == static_cast<ssize_t>(sizeof(byte)));
                ++stress_called;
            }))) == skan::core::StatusCode::Ok);
        write_byte(pair[1]);
    }
    for (int attempt = 0; attempt < 4 && stress_called < 100; ++attempt) {
        assert(engine.run_once(0) == skan::core::StatusCode::Ok);
    }
    assert(stress_called == 100);
    for (std::size_t index = 0U; index < stress_events.size(); ++index) {
        assert(engine.remove(*stress_events[index]) == skan::core::StatusCode::Ok);
        close_pair(stress_pairs[index].data());
    }

    int closed_fd = -1;
    {
        int closed_pair[2] = {-1, -1};
        assert(::pipe(closed_pair) == 0);
        closed_fd = closed_pair[0];
        assert(::close(closed_pair[0]) == 0);
        closed_pair[0] = -1;
        close_pair(closed_pair);
    }
    skan::io::Event closed_event(closed_fd, skan::io::EventMask::Read, [](skan::io::Event &) {});
    assert(engine.add(closed_event) == skan::core::StatusCode::IoError);
    assert(skan::io::IOEngine::set_nonblocking(closed_fd) == skan::core::StatusCode::IoError);

    int raii_pair[2] = {-1, -1};
    assert(::pipe(raii_pair) == 0);
    skan::io::Event raii_event(raii_pair[0], skan::io::EventMask::Read, [](skan::io::Event &) {});
    {
        skan::io::IOEngine raii_engine;
        assert(raii_engine.add(raii_event) == skan::core::StatusCode::Ok);
        assert(raii_event.registered());
    }
    assert(!raii_event.registered());
    close_pair(raii_pair);

    int shutdown_pair[2] = {-1, -1};
    assert(::pipe(shutdown_pair) == 0);
    skan::io::Event shutdown_event(shutdown_pair[0], skan::io::EventMask::Read, [](skan::io::Event &) {});
    assert(engine.add(shutdown_event) == skan::core::StatusCode::Ok);
    assert(engine.shutdown() == skan::core::StatusCode::Ok);
    assert(!shutdown_event.registered());
    assert(engine.shutdown() == skan::core::StatusCode::Ok);
    assert(engine.run_once(0) == skan::core::StatusCode::InvalidArgument);
    assert(engine.schedule(skan::io::TimerDuration::zero(), [] {}) == 0U);

    close_pair(readable_pair);
    close_pair(hangup_pair);
    close_pair(callback_pair);
    close_pair(cross_removal_pair);
    close_pair(added_pair);
    close_pair(modify_pair);
    close_pair(run_pair);
    close_pair(shutdown_pair);
    return 0;
}
