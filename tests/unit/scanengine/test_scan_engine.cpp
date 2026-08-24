#include <cassert>
#include <memory>

#include "scanengine/scan_engine.hpp"

int main()
{
    using namespace skan::scanengine;
    ScanEngine engine;
    assert(engine.validate() == skan::core::StatusCode::Ok);
    assert(engine.profile().id == TimingProfileId::T3);
    auto first = engine.create_group("first");
    auto second = engine.create_group("second");
    assert(first != nullptr && second != nullptr);
    assert(first->name() != second->name());

    auto invalid_profile = TimingProfile::for_id(TimingProfileId::T3);
    invalid_profile.max_parallelism = 0U;
    ScanEngine invalid{invalid_profile};
    assert(invalid.validate() == skan::core::StatusCode::InvalidArgument);
    assert(invalid.create_group("invalid") == nullptr);
    return 0;
}
