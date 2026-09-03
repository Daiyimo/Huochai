/* One deterministic API override; all other imports use generated forwarders. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

DWORD WINAPI DemoGetTickCount(void) {
    return 0xC0DEC0DEu;
}
