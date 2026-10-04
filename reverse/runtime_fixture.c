/* Controlled stand-ins for the UI and indexing engine. Never loads upstream
   code, installs a service, indexes disks or displays a window. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <wchar.h>
#include <stdlib.h>
#ifndef HUOCHAT_STOP_EVENT
#define HUOCHAT_STOP_EVENT L"Local\\HuoChatOfflineLauncherStoppingV1"
#endif

static WCHAR dir[1024],event_name[128];
static void Path(WCHAR *out,LPCWSTR leaf) { StringCchPrintfW(out,1100,L"%s%s",dir,leaf); }
static void Write(LPCWSTR leaf,const char *data) {
    WCHAR path[1100]; DWORD n; HANDLE f; Path(path,leaf);
    f=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);
    if(f!=INVALID_HANDLE_VALUE) { WriteFile(f,data,(DWORD)strlen(data),&n,NULL); CloseHandle(f); }
}
static BOOL Exists(LPCWSTR leaf) { WCHAR path[1100]; Path(path,leaf); return GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES; }
static BOOL StartEngine(PROCESS_INFORMATION *pi) {
    STARTUPINFOW si={0}; WCHAR exe[1100],cmd[1200]; si.cb=sizeof(si);
    Path(exe,L"hc_engine.exe"); StringCchPrintfW(cmd,1200,L"\"%s\"",exe);
    if(!CreateProcessW(exe,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,dir,&si,pi)) return FALSE;
    CloseHandle(pi->hThread); return TRUE;
}
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR args,int show) {
    WCHAR self[1024],path[1100]; DWORD n,i,hash=2166136261u; ULONGLONG started=GetTickCount64();
    HANDLE event; PROCESS_INFORMATION pi={0}; char pid[32];
    (void)a;(void)b;(void)show;
    n=GetModuleFileNameW(NULL,self,1024); StringCchCopyW(dir,1024,self);
    while(n && dir[n-1]!=L'\\') n--; dir[n]=0;
    for(i=0;i<n;i++) hash=(hash^(dir[i]|32))*16777619u;
    StringCchPrintfW(event_name,128,L"Local\\HuoChatFixtureExit%08lx",hash);
    if(wcsstr(self,L"hc_engine.exe")) {
        if(strstr(args,"-exit")) {
            event=OpenEventW(EVENT_MODIFY_STATE,FALSE,event_name);
            if(event) { SetEvent(event); CloseHandle(event); } return 0;
        }
        event=CreateEventW(NULL,TRUE,FALSE,event_name); if(!event) return 2;
        StringCchPrintfA(pid,32,"%lu",GetCurrentProcessId()); Write(L"engine.ready",pid);
        WaitForSingleObject(event,120000);
        {
            HANDLE f; DWORD bytes,delay=150; char value[32]={0};
            Path(path,L"test-delay-ms"); f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
            if(f!=INVALID_HANDLE_VALUE) { if(ReadFile(f,value,31,&bytes,NULL)) delay=strtoul(value,NULL,10); CloseHandle(f); }
            Sleep(delay);
        }
        Path(path,L"Data\\Index"); CreateDirectoryW(path,NULL);
        Write(L"Data\\Index\\Everything.db","fixture-index-saved");
        CloseHandle(event); return 0;
    }
    if(!StartEngine(&pi)) return 3;
    {
        PROCESS_INFORMATION child={0}; STARTUPINFOW si={0}; WCHAR exe[1100],cmd[1200]; DWORD code=999;
        Path(exe,L"test_environment.exe");StringCchPrintfW(cmd,1200,L"\"%s\"",exe);si.cb=sizeof(si);
        if(CreateProcessW(exe,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,dir,&si,&child)) {
            if(WaitForSingleObject(child.hProcess,30000)==WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess,&code);
            else TerminateProcess(child.hProcess,999);
            CloseHandle(child.hProcess);CloseHandle(child.hThread);
        }
        StringCchPrintfA(pid,32,"%lu",code);Write(L"env-harness.exit",pid);
    }
    Write(L"ui.args",args);
    {
        WCHAR value[1024]; char utf8[4096];
        const WCHAR *names[]={L"APPDATA",L"LOCALAPPDATA",L"TEMP",L"TMP"};
        const WCHAR *files[]={L"env-appdata",L"env-localappdata",L"env-temp",L"env-tmp"};
        for(i=0;i<4;i++) {
            GetEnvironmentVariableW(names[i],value,1024);
            WideCharToMultiByte(CP_UTF8,0,value,-1,utf8,sizeof(utf8),NULL,NULL); Write(files[i],utf8);
        }
    }
    StringCchPrintfA(pid,32,"%lu",GetCurrentProcessId()); Write(L"ui.ready",pid);
    while(GetTickCount64()-started<120000 && !Exists(L"test-stop")) {
        if(Exists(L"test-restart")) {
            Path(path,L"test-restart"); DeleteFileW(path);
            TerminateProcess(pi.hProcess,0); WaitForSingleObject(pi.hProcess,5000); CloseHandle(pi.hProcess);
            if(!StartEngine(&pi)) return 4;
        }
        Sleep(50);
    }
    /* Model a tray exit request before the UI finishes its own teardown. */
    event=OpenEventW(EVENT_MODIFY_STATE,FALSE,HUOCHAT_STOP_EVENT);
    if(event) { SetEvent(event);CloseHandle(event); }
    Path(path,L"test-stop");DeleteFileW(path);
    Write(L"ui.stopping",pid);
    Sleep(500);
    if(Exists(L"test-late-engine")) {
        PROCESS_INFORMATION late={0};
        if(StartEngine(&late)) {
            StringCchPrintfA(pid,32,"%lu",late.dwProcessId);Write(L"late-engine.pid",pid);
            CloseHandle(late.hProcess);
        }
    }
    Sleep(500);
    CloseHandle(pi.hProcess); return 0;
}
