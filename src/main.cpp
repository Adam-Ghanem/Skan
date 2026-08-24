#include <cstdlib>
#include <iostream>
#include <string_view>

#include "core/constants.hpp"

namespace {

void print_help()
{
    std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n'
              << "Nmap-inspired modular network scanning platform\n\n"
              << "Usage:\n"
              << "  skan [options]\n\n"
              << "Options:\n"
              << "  --help       Show help\n"
              << "  --version    Show version\n\n"
              << "Status:\n"
              << "  Phase 0 — Foundation\n";
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << skan::core::constants::SKAN_VERSION_STRING << '\n';
        return EXIT_SUCCESS;
    }

    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        print_help();
        return EXIT_SUCCESS;
    }

    std::cerr << "Error: unknown or missing argument. Use --help for usage.\n";
    return EXIT_FAILURE;
}
