#include <stdio.h>

void copy_name(char *destination, size_t size, const char *source) {
    snprintf(destination, size, "%s", source);
}
