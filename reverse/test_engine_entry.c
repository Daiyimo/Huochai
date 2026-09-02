#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
typedef LPWSTR (WINAPI *COMMANDW)(void);
typedef LPSTR (WINAPI *COMMANDA)(void);
typedef BOOL (WINAPI *NOTIFYW)(DWORD,PNOTIFYICONDATAW);
#define CHECK(x) do { if(!(x)) { printf("Engine entry failed line %d: %s\n",__LINE__,#x); return 1; } } while(0)
int wmain(int argc,WCHAR **argv) {
    HMODULE guard=LoadLibraryW(L"hcg.dll"); COMMANDW wide; COMMANDA ansi; LPWSTR text; NOTIFYW notify;
    CHECK(guard);wide=(COMMANDW)GetProcAddress(guard,"GetCommandLineW");ansi=(COMMANDA)GetProcAddress(guard,"GetCommandLineA");CHECK(wide && ansi);
    text=wide();CHECK(text==wide());
    if(argc>1 && !lstrcmpW(argv[1],L"expect-unchanged")) {
        CHECK(!lstrcmpW(text,GetCommandLineW()));CHECK(!strcmp(ansi(),GetCommandLineA()));
        puts("Command-line passthrough passed.");return 0;
    }
    CHECK(wcsstr(text,L" -config \"") && wcsstr(text,L"Data\\Index.ini\""));
    CHECK(wcsstr(text,L" -db \"") && wcsstr(text,L"Data\\Index\\Everything.db\""));
    CHECK(wcsstr(text,L" -startup"));CHECK(strstr(ansi()," -config \"") && strstr(ansi()," -startup"));
    notify=(NOTIFYW)GetProcAddress(guard,"Shell_NotifyIconW");CHECK(notify);
    CHECK(notify(NIM_ADD,NULL)); /* engine route must never call Shell with this */
    {
        typedef FARPROC (WINAPI *RESOLVE)(HMODULE,LPCSTR);
        RESOLVE resolve=(RESOLVE)GetProcAddress(guard,"GetProcAddress");CHECK(resolve);
        CHECK(resolve(LoadLibraryW(L"shell32.dll"),"Shell_NotifyIconW")== (FARPROC)notify);
    }
    puts("Engine entry passed: explicit config/cache, background startup, stable A/W command lines, engine tray suppressed.");return 0;
}
