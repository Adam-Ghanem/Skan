#include <cassert>
#include <iostream>
#include <sstream>
#include <string>

#include "core/log.hpp"

int main()
{
    skan::log::set_minimum_level(skan::log::Level::Info);
    assert(skan::log::minimum_level() == skan::log::Level::Info);
    std::ostringstream default_capture;
    std::streambuf *original = std::cerr.rdbuf(default_capture.rdbuf());
    skan::log::debug("hidden debug");
    skan::log::info("visible info");
    std::cerr.rdbuf(original);
    assert(default_capture.str().find("hidden debug") == std::string::npos);
    assert(default_capture.str().find("visible info") != std::string::npos);

    skan::log::set_minimum_level(skan::log::Level::Debug);
    assert(skan::log::minimum_level() == skan::log::Level::Debug);
    std::ostringstream debug_capture;
    original = std::cerr.rdbuf(debug_capture.rdbuf());
    skan::log::debug("visible debug");
    std::cerr.rdbuf(original);
    assert(debug_capture.str().find("visible debug") != std::string::npos);

    skan::log::set_minimum_level(skan::log::Level::Info);
    return 0;
}
