/* Authored teaching fixture. No HuoChat or Everything binary is required. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

volatile char demo_endpoint[] = "https://example.invalid/demo";

int main(int argc, char **argv) {
    const char expected[] = "about:blank";
    unsigned i; int cleaned = 1;
    int hooked = GetTickCount() == 0xC0DEC0DEu;
    for (i = 0; i < sizeof(expected)-1; ++i)
        if (demo_endpoint[i] != expected[i]) cleaned = 0;
    if (argc != 2) return 2;
    printf("hooked=%d url_cleaned=%d\n", hooked, cleaned);
    if (!strcmp(argv[1], "original")) return cleaned ? 3 : 0;
    if (!strcmp(argv[1], "patched")) return hooked && cleaned ? 0 : 4;
    return 2;
}
