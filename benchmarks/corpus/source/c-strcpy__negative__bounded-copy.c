#include <string.h>

void load(char *dst, size_t cap, char **argv) {
    // strncpy takes the destination size, so the copy cannot run past it.
    strncpy(dst, argv[1], cap - 1);
    dst[cap - 1] = '\0';
}
