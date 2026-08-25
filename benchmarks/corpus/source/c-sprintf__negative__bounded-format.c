#include <stdio.h>

void render(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "hello %s", name);
}
