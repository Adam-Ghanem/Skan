#include "net/unique_fd.hpp"

#include <unistd.h>

namespace skan::net::detail {

UniqueFd::~UniqueFd() noexcept
{
    reset();
}

UniqueFd::UniqueFd(UniqueFd &&other) noexcept : file_descriptor_(other.release()) {}

UniqueFd &UniqueFd::operator=(UniqueFd &&other) noexcept
{
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

int UniqueFd::release() noexcept
{
    const int result = file_descriptor_;
    file_descriptor_ = -1;
    return result;
}

void UniqueFd::reset(int file_descriptor) noexcept
{
    if (file_descriptor_ >= 0) {
        (void)::close(file_descriptor_);
    }
    file_descriptor_ = file_descriptor;
}

} // namespace skan::net::detail
