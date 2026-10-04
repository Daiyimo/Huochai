#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "startup.h"
#define CHECK(x) do { if(!(x)) { printf("Startup test failed line %d: %s\n",__LINE__,#x); return 1; } } while(0)
typedef LSTATUS (WINAPI *SETW)(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
typedef LSTATUS (WINAPI *SETA)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
typedef LSTATUS (WINAPI *SHSETW)(HKEY,LPCWSTR,LPCWSTR,DWORD,const void*,DWORD);
typedef LSTATUS (WINAPI *SHSETA)(HKEY,LPCSTR,LPCSTR,DWORD,const void*,DWORD);
static LONG Set(HKEY key,LPCWSTR name,LPCWSTR value) {
    return RegSetValueExW(key,name,0,REG_SZ,(const BYTE*)value,((DWORD)wcslen(value)+1)*2);
}
static BOOL Equal(HKEY key,LPCWSTR name,LPCWSTR expected) {
    WCHAR value[STARTUP_CAP];DWORD size=sizeof(value),type;
    return RegQueryValueExW(key,name,NULL,&type,(LPBYTE)value,&size)==ERROR_SUCCESS && type==REG_SZ && !lstrcmpW(value,expected);
}
int wmain(int argc,WCHAR **argv) {
    WCHAR dir[STARTUP_CAP],native[STARTUP_CAP],expected[STARTUP_CAP],otherpath[STARTUP_CAP];
    CHAR ansi[STARTUP_CAP],suba[STARTUP_CAP]; HKEY key,other; HMODULE module; SETW setw; SETA seta; SHSETW shw;SHSETA sha;
    CHECK(argc==2);CHECK(SUCCEEDED(StringCchPrintfW(dir,STARTUP_CAP,L"%s\\",argv[1])));
    CHECK(SUCCEEDED(StringCchPrintfW(native,STARTUP_CAP,L"\"%sHuoChat.exe\" -s",dir)));
    CHECK(StartupCommand(dir,expected));
    CHECK(RegCreateKeyExW(HKEY_CURRENT_USER,HUOCHAT_STARTUP_KEY,0,NULL,0,KEY_ALL_ACCESS,NULL,&key,NULL)==0);
    CHECK(IsStartupKey(key));
    CHECK(SUCCEEDED(StringCchPrintfW(otherpath,STARTUP_CAP,L"%s\\Other",HUOCHAT_STARTUP_KEY)));
    CHECK(RegCreateKeyExW(HKEY_CURRENT_USER,otherpath,0,NULL,0,KEY_ALL_ACCESS,NULL,&other,NULL)==0);
    CHECK(!IsStartupKey(other));
    module=LoadLibraryW(L"startup-test.dll");CHECK(module);
    setw=(SETW)GetProcAddress(module,"RegSetValueExW");seta=(SETA)GetProcAddress(module,"RegSetValueExA");CHECK(setw && seta);
    shw=(SHSETW)GetProcAddress(module,"SHSetValueW");sha=(SHSETA)GetProcAddress(module,"SHSetValueA");CHECK(shw && sha);
    /* UI enable, disable and enable again: only the exact own Run value changes. */
    CHECK(setw(key,L"HuoChat",0,REG_SZ,(const BYTE*)native,((DWORD)wcslen(native)+1)*2)==0);
    CHECK(Equal(key,L"HuoChat",expected));CHECK(RegDeleteValueW(key,L"HuoChat")==0);
    CHECK(ReconcileStartup(dir)==0);CHECK(!Equal(key,L"HuoChat",expected));
    CHECK(WideCharToMultiByte(CP_ACP,0,native,-1,ansi,sizeof(ansi),NULL,NULL));
    CHECK(seta(key,"HuoChat",0,REG_SZ,(const BYTE*)ansi,(DWORD)strlen(ansi)+1)==0);CHECK(Equal(key,L"HuoChat",expected));
    CHECK(setw(other,L"HuoChat",0,REG_SZ,(const BYTE*)native,((DWORD)wcslen(native)+1)*2)==0);CHECK(Equal(other,L"HuoChat",native));
    CHECK(setw(key,L"OtherApp",0,REG_SZ,(const BYTE*)native,((DWORD)wcslen(native)+1)*2)==0);CHECK(Equal(key,L"OtherApp",native));
    CHECK(Set(key,L"HuoChat",L"C:\\other\\app.exe")==0);CHECK(ReconcileStartup(dir)==0);CHECK(Equal(key,L"HuoChat",L"C:\\other\\app.exe"));
    CHECK(Set(key,L"HuoChat",native)==0);CHECK(ReconcileStartup(dir)==0);CHECK(Equal(key,L"HuoChat",expected));
    CHECK(shw(HKEY_CURRENT_USER,HUOCHAT_STARTUP_KEY,L"HuoChat",REG_SZ,native,(DWORD)wcslen(native)*2)==0);CHECK(Equal(key,L"HuoChat",expected));
    CHECK(WideCharToMultiByte(CP_ACP,0,HUOCHAT_STARTUP_KEY,-1,suba,sizeof(suba),NULL,NULL));
    CHECK(sha(HKEY_CURRENT_USER,suba,"HuoChat",REG_SZ,ansi,(DWORD)strlen(ansi))==0);CHECK(Equal(key,L"HuoChat",expected));
    CHECK(RegSetValueExW(key,L"HuoChat",0,REG_SZ,(const BYTE*)native,(DWORD)wcslen(native)*2)==0);
    CHECK(ReconcileStartup(dir)==0);CHECK(Equal(key,L"HuoChat",expected));
    /* A value longer than the compare buffer used to be reported as a failure on
       every launch, so the entry could never be examined or repaired. It is not
       ours and must simply be left exactly as it is. */
    {
        WCHAR foreign[RUN_VALUE_CAP],back[RUN_VALUE_CAP];DWORD i,bytes=sizeof(back),type;
        for(i=0;i+1<RUN_VALUE_CAP/2;i++)foreign[i]=L'x';foreign[RUN_VALUE_CAP/2-1]=0;
        CHECK(Set(key,L"HuoChat",foreign)==0);
        CHECK(ReconcileStartup(dir)==0);
        CHECK(RegQueryValueExW(key,L"HuoChat",NULL,&type,(LPBYTE)back,&bytes)==0);
        CHECK(!lstrcmpW(back,foreign));
        CHECK(RegDeleteValueW(key,L"HuoChat")==0);
    }
    RegCloseKey(other);RegCloseKey(key);FreeLibrary(module);
    puts("Startup passed: A/W enable-disable-enable, exact-key scoping, disabled state, other apps, existing-entry repair, over-long entry left alone.");return 0;
}
