#include <stdio.h>
#include <string.h>

#include "core/constants.h"

static void skan_print_help(const char *program_name)
{
    (void)printf("Usage: %s [OPTION]\n\n", program_name);
    (void)printf("Skan is currently in Phase 0, providing the project foundation.\n");
    (void)printf("Scanning functionality is under development.\n\n");
    (void)printf("Options:\n");
    (void)printf("  --help       Show this help message.\n");
    (void)printf("  --version    Show the Skan version.\n");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        (void)printf("Skan %s\n", SKAN_VERSION);
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        skan_print_help(argv[0]);
        return 0;
    }

    (void)fprintf(stderr, "Error: unknown or missing argument. Use --help for usage.\n");
    return 2;
}
