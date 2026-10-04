#ifndef HUOCHAT_ENGINE_ENTRY_H
#define HUOCHAT_ENGINE_ENTRY_H
#include <strsafe.h>

/* Everything constructs its default INI name at runtime. Explicit command-line
   paths cover normal starts and restarts; replacing filename literals does not. */
static INIT_ONCE engine_once=INIT_ONCE_STATIC_INIT;
static BOOL own_engine;
static LPWSTR engine_command_w;
static LPSTR engine_command_a;

static BOOL CALLBACK InitEngineEntry(PINIT_ONCE once,PVOID parameter,PVOID *context) {
    WCHAR module[1024],exe[1024],suffix[2300]; LPWSTR original=GetCommandLineW(),*args;
    DWORD n; int argc,i,bytes; size_t length,extra; BOOL control=FALSE;
    (void)once;(void)parameter;(void)context;
    n=GetModuleFileNameW(self_module,module,1024);
    /* Without this identity the command line below cannot be scoped, and the
       engine would start with its original arguments and its default config.
       The launcher already refuses paths this long, so this only guards the
       invariant instead of silently dropping it. */
    if(!n || n>=1024 || !GetModuleFileNameW(NULL,exe,1024)) ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    while(n && module[n-1]!=L'\\' && module[n-1]!=L'/') --n;
    if(!n || FAILED(StringCchCopyW(module+n,1024-n,L"hc_engine.exe"))) ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    own_engine=!lstrcmpiW(module,exe);
    if(!own_engine) return TRUE;
    module[n]=0;
    args=CommandLineToArgvW(original,&argc);
    if(!args) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
    for(i=1;i<argc;i++) {
        if(!lstrcmpiW(args[i],L"-svc") || !lstrcmpiW(args[i],L"-service") ||
           !lstrcmpiW(args[i],L"-client-svc") || !lstrcmpiW(args[i],L"-exit") ||
           !lstrcmpiW(args[i],L"-quit") || !lstrcmpiW(args[i],L"-install-service") ||
           !lstrcmpiW(args[i],L"-uninstall-service") || !lstrcmpiW(args[i],L"-uninstall") ||
           !lstrcmpiW(args[i],L"-help") || !lstrcmpiW(args[i],L"/?")) control=TRUE;
    }
    LocalFree(args);
    /* Service/control processes must retain their original command semantics. */
    if(control) return TRUE;
    if(FAILED(StringCchPrintfW(suffix,2300,L" -config \"%sData\\Index.ini\" -db \"%sData\\Index\\Everything.db\" -startup",module,module)))
        ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    length=lstrlenW(original); extra=lstrlenW(suffix);
    /* A self-relaunch may already carry exactly these arguments. */
    if(length>=extra && !lstrcmpW(original+length-extra,suffix)) extra=0;
    if(length+extra>=32767) ExitProcess(ERROR_FILENAME_EXCED_RANGE);
    engine_command_w=(LPWSTR)HeapAlloc(GetProcessHeap(),0,(length+extra+1)*sizeof(WCHAR));
    if(!engine_command_w) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
    CopyMemory(engine_command_w,original,(length+1)*sizeof(WCHAR));
    if(extra) CopyMemory(engine_command_w+length,suffix,(extra+1)*sizeof(WCHAR));
    bytes=WideCharToMultiByte(CP_ACP,0,engine_command_w,-1,NULL,0,NULL,NULL);
    engine_command_a=(LPSTR)HeapAlloc(GetProcessHeap(),0,bytes);
    if(!bytes || !engine_command_a || !WideCharToMultiByte(CP_ACP,0,engine_command_w,-1,engine_command_a,bytes,NULL,NULL))
        ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
    return TRUE;
}
static BOOL IsOwnEngine(void) {
    if(!InitOnceExecuteOnce(&engine_once,InitEngineEntry,NULL,NULL)) ExitProcess(GetLastError());
    return own_engine;
}
LPWSTR WINAPI Guard_GetCommandLineW(void) { IsOwnEngine(); return engine_command_w ? engine_command_w:GetCommandLineW(); }
LPSTR WINAPI Guard_GetCommandLineA(void) { IsOwnEngine(); return engine_command_a ? engine_command_a:GetCommandLineA(); }
BOOL WINAPI Guard_Shell_NotifyIconW(DWORD message,PNOTIFYICONDATAW data) {
    return IsOwnEngine() ? TRUE:Shell_NotifyIconW(message,data);
}
BOOL WINAPI Guard_Shell_NotifyIconA(DWORD message,PNOTIFYICONDATAA data) {
    return IsOwnEngine() ? TRUE:Shell_NotifyIconA(message,data);
}
#endif
