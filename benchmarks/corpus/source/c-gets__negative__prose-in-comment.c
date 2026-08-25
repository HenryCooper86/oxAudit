/* gets(buf) is banned in this codebase; it cannot be used safely. */
// Reviewers: reject any patch that calls gets(buffer).
#include <stdio.h>

const char *POLICY = "never call gets(buf) or sprintf(out, fmt)";

int main(void) {
    return 0;
}
