#include <cassert>
#include <algorithm>
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

    std::ostringstream hostile_capture;
    original = std::cerr.rdbuf(hostile_capture.rdbuf());
    skan::log::error(std::string("safe") + '\x1b' + "]0;owned\a\n" + "tail\xe2\x80\xae");
    std::cerr.rdbuf(original);
    const std::string hostile_log = hostile_capture.str();
    assert(hostile_log.find('\x1b') == std::string::npos);
    assert(hostile_log.find('\a') == std::string::npos);
    assert(hostile_log.find("\xe2\x80\xae") == std::string::npos);
    assert(static_cast<std::size_t>(std::count(hostile_log.begin(), hostile_log.end(), '\n')) == 1U);

    std::ostringstream terminal_capture;
    skan::log::write_to(terminal_capture, true, skan::log::Level::Warn, "coordinated");
    assert(terminal_capture.str().starts_with("\r\x1b[2K"));
    assert(terminal_capture.str().ends_with("coordinated\n"));

    skan::log::set_minimum_level(skan::log::Level::Info);
    return 0;
}
