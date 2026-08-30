#include <cassert>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

#include "core/log.hpp"

int main()
{
    (void)::unsetenv("SKAN_LOG");
    std::ostringstream default_capture;
    std::streambuf *original = std::cerr.rdbuf(default_capture.rdbuf());
    skan::log::debug("hidden debug");
    skan::log::info("visible info");
    std::cerr.rdbuf(original);
    assert(default_capture.str().find("hidden debug") == std::string::npos);
    assert(default_capture.str().find("visible info") != std::string::npos);

    (void)::setenv("SKAN_LOG", "debug", 1);
    std::ostringstream debug_capture;
    original = std::cerr.rdbuf(debug_capture.rdbuf());
    skan::log::debug("visible debug");
    std::cerr.rdbuf(original);
    assert(debug_capture.str().find("visible debug") != std::string::npos);

    (void)::unsetenv("SKAN_LOG");
    return 0;
}
