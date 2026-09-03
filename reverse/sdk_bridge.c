/* Both the SDK and HuoChat's direct IPC query path use this lookup.
   Other USER32 exports are forwarders; query layout and callbacks stay intact. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "backend.h"
static HMODULE own_module;
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;if(reason==DLL_PROCESS_ATTACH)own_module=module;return TRUE;
}
HWND WINAPI Backend_FindWindowW(LPCWSTR name,LPCWSTR title) {
    BackendPaths paths;HWND window;DWORD pid,chars;HANDLE process;WCHAR exe[PATH_CAP];
    if((ULONG_PTR)name>0xffff && (!lstrcmpW(name,L"EVERYTHING_TASKBAR_NOTIFICATION") || !lstrcmpW(name,L"EVERYTHING"))) {
        if(!BackendFromModule(&paths,own_module) || !paths.modern)return NULL;
        /* HuoChat's startup gate also checks the ordinary Everything window. */
        if(!lstrcmpW(name,L"EVERYTHING"))StringCchPrintfW(paths.window,128,L"EVERYTHING_(%s)",paths.instance);
        window=FindWindowW(paths.window,title);if(!window)return NULL;
        GetWindowThreadProcessId(window,&pid);process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
        if(!process)return NULL;chars=PATH_CAP;
        if(!QueryFullProcessImageNameW(process,0,exe,&chars) || !SameBackendFile(exe,paths.exe))window=NULL;
        CloseHandle(process);return window;
    }
    return FindWindowW(name,title);
}
