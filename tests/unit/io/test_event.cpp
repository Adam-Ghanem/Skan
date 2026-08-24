#include <cassert>
#include <unistd.h>

#include "io/event.hpp"
#include "io/io_engine.hpp"

int main()
{
    int descriptors[2] = {-1, -1};
    assert(::pipe(descriptors) == 0);

    int context_value = 42;
    bool callback_called = false;
    skan::io::Event event(
        descriptors[0],
        skan::io::EventMask::Read | skan::io::EventMask::Error,
        [&callback_called](const skan::io::Event &) { callback_called = true; },
        &context_value);

    assert(event.file_descriptor() == descriptors[0]);
    assert(skan::io::has_event(event.mask(), skan::io::EventMask::Read));
    assert(skan::io::has_event(event.mask(), skan::io::EventMask::Error));
    assert(!skan::io::has_event(event.mask(), skan::io::EventMask::Write));
    assert(event.context() == &context_value);
    assert(!event.registered());
    assert(event.ready_mask() == skan::io::EventMask::None);

    event.set_mask(skan::io::EventMask::Write);
    assert(event.mask() == skan::io::EventMask::Write);

    skan::io::IOEngine engine;
    assert(engine.initialization_status() == skan::core::StatusCode::Ok);
    assert(engine.add(event) == skan::core::StatusCode::Ok);
    assert(event.registered());
    assert(engine.remove(event) == skan::core::StatusCode::Ok);
    assert(!event.registered());
    assert(!callback_called);
    assert(engine.remove(event) == skan::core::StatusCode::NotFound);

    assert(::close(descriptors[0]) == 0);
    assert(::close(descriptors[1]) == 0);
    return 0;
}
