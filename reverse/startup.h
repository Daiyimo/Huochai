#ifndef HUOCHAT_STARTUP_H
#define HUOCHAT_STARTUP_H
#include <windows.h>
#include <strsafe.h>
#include <wchar.h>
#ifndef HUOCHAT_STARTUP_KEY
#define HUOCHAT_STARTUP_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#endif
#define STARTUP_CAP 1024

static BOOL StartupCommand(LPCWSTR dir, WCHAR *command) {
    WCHAR marker[STARTUP_CAP], entry[STARTUP_CAP];
    if(FAILED(StringCchPrintfW(marker,STARTUP_CAP,L"%s.package.ini",dir))) return FALSE;
    GetPrivateProfileStringW(L"Package",L"entry",L"",entry,STARTUP_CAP,marker);
    if(!entry[0] || GetFileAttributesW(entry)==INVALID_FILE_ATTRIBUTES) {
        if(FAILED(StringCchPrintfW(entry,STARTUP_CAP,L"%sHuoChat_launcher.exe",dir))) return FALSE;
    }
    return SUCCEEDED(StringCchPrintfW(command,STARTUP_CAP,L"\"%s\" -s",entry));
}

/* Do not rewrite another program's value merely because it is called HuoChat. */
static BOOL IsOwnStartup(LPCWSTR value, LPCWSTR dir, LPCWSTR prior) {
    WCHAR expected[STARTUP_CAP]; const WCHAR *p=value; size_t n;
    if(!value || !*value) return FALSE;
    if(*p==L'"') p++;
    if(prior && *prior && !lstrcmpiW(value,prior)) return TRUE;
    if(FAILED(StringCchPrintfW(expected,STARTUP_CAP,L"%sHuoChat.exe",dir))) return FALSE;
    n=wcslen(expected);
    if(!_wcsnicmp(p,expected,n) && (!p[n] || p[n]==L'"' || p[n]==L' ')) return TRUE;
    if(FAILED(StringCchPrintfW(expected,STARTUP_CAP,L"%sHuoChat_launcher.exe",dir))) return FALSE;
    n=wcslen(expected);
    return !_wcsnicmp(p,expected,n) && (!p[n] || p[n]==L'"' || p[n]==L' ');
}

/* KeyNameInformation has no KEY_QUERY_VALUE access requirement. Comparing the
   complete names also handles callers opening Run relative to an existing key. */
static BOOL IsStartupKey(HKEY key) {
    typedef LONG (NTAPI *QUERYKEY)(HANDLE,int,PVOID,ULONG,PULONG);
    struct KeyName { ULONG bytes; WCHAR name[1024]; } a,b;
    QUERYKEY query=(QUERYKEY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryKey");
    HKEY expected; ULONG used; BOOL same=FALSE;
    if(!query || RegOpenKeyExW(HKEY_CURRENT_USER,HUOCHAT_STARTUP_KEY,0,KEY_QUERY_VALUE,&expected)!=ERROR_SUCCESS) return FALSE;
    if(query(key,3,&a,sizeof(a),&used)>=0 && query(expected,3,&b,sizeof(b),&used)>=0 &&
       a.bytes==b.bytes && a.bytes<=sizeof(a.name))
        same=CompareStringOrdinal(a.name,a.bytes/2,b.name,b.bytes/2,TRUE)==CSTR_EQUAL;
    RegCloseKey(expected); return same;
}

/* Preserve the enabled/disabled state. Save the old location only after repair
   succeeds, so a denied registry write can be retried on the next launch. */
static LONG ReconcileStartup(LPCWSTR dir) {
    WCHAR state[STARTUP_CAP],oldroot[STARTUP_CAP],oldcommand[STARTUP_CAP],value[STARTUP_CAP],command[STARTUP_CAP];
    DWORD size=sizeof(value)-2,type; HKEY key; LONG status;
    if(FAILED(StringCchPrintfW(state,STARTUP_CAP,L"%sData\\layout.ini",dir)) || !StartupCommand(dir,command)) return ERROR_BUFFER_OVERFLOW;
    GetPrivateProfileStringW(L"Layout",L"root",L"",oldroot,STARTUP_CAP,state);
    GetPrivateProfileStringW(L"Layout",L"startup",L"",oldcommand,STARTUP_CAP,state);
    status=RegOpenKeyExW(HKEY_CURRENT_USER,HUOCHAT_STARTUP_KEY,0,KEY_QUERY_VALUE|KEY_SET_VALUE,&key);
    if(status==ERROR_SUCCESS) {
        status=RegQueryValueExW(key,L"HuoChat",NULL,&type,(LPBYTE)value,&size);
        if(status==ERROR_SUCCESS && size<sizeof(value)) value[size/2]=0;
        if(status==ERROR_SUCCESS && type==REG_SZ && size>=2 && size%2==0 && size<sizeof(value) &&
           (IsOwnStartup(value,dir,command) || (oldroot[0] && IsOwnStartup(value,oldroot,oldcommand))))
            status=RegSetValueExW(key,L"HuoChat",0,REG_SZ,(const BYTE*)command,((DWORD)wcslen(command)+1)*2);
        RegCloseKey(key);
    }
    if(status==ERROR_FILE_NOT_FOUND) status=ERROR_SUCCESS;
    if(status==ERROR_SUCCESS) {
        if(!WritePrivateProfileStringW(L"Layout",L"root",dir,state) ||
           !WritePrivateProfileStringW(L"Layout",L"startup",command,state)) status=GetLastError();
    }
    return status;
}
#endif
