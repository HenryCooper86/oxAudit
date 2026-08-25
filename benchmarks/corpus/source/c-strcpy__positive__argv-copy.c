#include <string.h>

void load(char *dst, int argc, char **argv) {
    if (argc > 1) {
        strcpy(dst, argv[1]);
    }
}
