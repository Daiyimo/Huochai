#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static void AttachEngine(DWORD parent,HANDLE job,LPCWSTR expected) {
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process; WCHAR image[1024]; DWORD count;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(entry.th32ParentProcessID!=parent || lstrcmpiW(entry.szExeFile,L"hc_engine.exe")) continue;
        process=OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!process) continue;
        count=1024;
        if(QueryFullProcessImageNameW(process,0,image,&count) && !lstrcmpiW(image,expected)) AssignProcessToJobObject(job,process);
        CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
}

/* Both sides come from the OS as full paths, so compare them directly.
   Deliberately no GetLongPathNameW: it rewrites "EXAMPL~1" to "example-user",
   which breaks the prefix test depending on which side was converted. */
static BOOL InsideDir(LPCWSTR candidate, LPCWSTR dir) {
    DWORD n;
    if(!candidate || !*candidate) return FALSE;
    n=lstrlenW(dir);
    if((DWORD)lstrlenW(candidate)<n) return FALSE;
    return CompareStringW(LOCALE_INVARIANT,NORM_IGNORECASE,candidate,n,dir,n)==CSTR_EQUAL;
}

/* SERVICE_DELETE is 0x10000; winsvc.h hides it under WIN32_LEAN_AND_MEAN. */
#define SVC_DELETE 0x00010000L

/* The engine writes Everything.db only on a clean exit. Verified: a plain
   "-startup" instance flushes it when asked to "-exit"; a "-svc" service
   instance ignores -exit and takes about a minute to go away. Asking every
   instance and bounding the wait gives the plain one time to flush while the
   service one is terminated as the fallback, which loses nothing because it
   never wrote the cache in the first place. */
static void RequestEngineExit(LPCWSTR selfdir) {
    STARTUPINFOW si={0}; PROCESS_INFORMATION pi={0}; WCHAR cmd[1200];
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process; WCHAR image[1024]; DWORD count;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(lstrcmpiW(entry.szExeFile,L"hc_engine.exe")) continue;
        process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!process) continue;
        count=1024;
        if(QueryFullProcessImageNameW(process,0,image,&count) && InsideDir(image,selfdir)) {
            lstrcpyW(cmd,L"\""); lstrcatW(cmd,image); lstrcatW(cmd,L"\" -exit");
            si.cb=sizeof(si);
            if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,selfdir,&si,&pi)) {
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            }
        }
        CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
}

static void StopEngineService(LPCWSTR selfdir) {
    SC_HANDLE scm=NULL,svc=NULL; WCHAR path[1024]; SERVICE_STATUS_PROCESS st={0};
    DWORD need=0; LPQUERY_SERVICE_CONFIGW cfg=NULL;
    scm=OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT);
    if(!scm) return;    svc=OpenServiceW(scm,L"Everything",
        SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_STOP|SVC_DELETE);
    if(!svc) { CloseServiceHandle(scm); return; }
    need=0;
    QueryServiceConfigW(svc,NULL,0,&need);
    if(need) cfg=(LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),0,need);
    if(cfg && QueryServiceConfigW(svc,cfg,need,&need) && cfg->lpBinaryPathName) {
        /* The path may be quoted; skip the quote before comparing. */
        LPCWSTR bin=cfg->lpBinaryPathName;
        if(*bin==L'"') ++bin;
        lstrcpyW(path,bin);
        { WCHAR *q=path; while(*q && *q!=L'"') ++q; *q=0; }
        if(InsideDir(path,selfdir)) {
            ControlService(svc,SERVICE_CONTROL_STOP,(LPSERVICE_STATUS)&st);
            DeleteService(svc);
        }
    }
    if(cfg) HeapFree(GetProcessHeap(),0,cfg);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
}

static BOOL EngineRunning(LPCWSTR selfdir) {
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process; WCHAR image[1024]; DWORD count; BOOL found=FALSE;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return FALSE;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(lstrcmpiW(entry.szExeFile,L"hc_engine.exe")) continue;
        process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!process) continue;
        count=1024;
        if(QueryFullProcessImageNameW(process,0,image,&count) && InsideDir(image,selfdir)) found=TRUE;
        CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
    return found;
}

static void StopEngineProcesses(LPCWSTR selfdir) {
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process; WCHAR image[1024]; DWORD count;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(lstrcmpiW(entry.szExeFile,L"hc_engine.exe")) continue;
        process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE,FALSE,entry.th32ProcessID);
        if(!process) continue;
        count=1024;
        if(QueryFullProcessImageNameW(process,0,image,&count) && InsideDir(image,selfdir))
            TerminateProcess(process,0);
        CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
}

int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR args,int show) {
    WCHAR path[1024],command[1100],engine[1100],dir[1024]; DWORD n;
    STARTUPINFOW si={0}; PROCESS_INFORMATION pi={0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; HANDLE job,mutex;
    (void)instance;(void)previous;(void)args;(void)show;
    mutex=CreateMutexW(NULL,TRUE,L"Local\\HuoChatOfflineLauncherV1");
    if(!mutex || GetLastError()==ERROR_ALREADY_EXISTS) return 1;
    n=GetModuleFileNameW(NULL,path,1024);
    if(!n || n>990) return 2;
    while(n && path[n-1]!=L'\\') --n;
    path[n]=0;
    lstrcpyW(dir,path);
    lstrcpyW(command,L"\""); lstrcatW(command,path); lstrcatW(command,L"HuoChat.exe\"");
    lstrcpyW(engine,path); lstrcatW(engine,L"hc_engine.exe");
    job=CreateJobObjectW(NULL,NULL);
    /* Applications the user opens must not be killed when the search UI exits.
       Only the matching engine child is explicitly added back to this job. */
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if(!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) return 3;
    si.cb=sizeof(si);
    if(!CreateProcessW(NULL,command,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,path,&si,&pi)) {
        MessageBoxW(NULL,L"The offline program could not start. Keep hcn.dll and hcg.dll beside HuoChat.exe.",L"HuoChat Offline",MB_ICONERROR);
        CloseHandle(job); return 4;
    }
    if(!AssignProcessToJobObject(job,pi.hProcess)) {
        TerminateProcess(pi.hProcess,5); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job); return 5;
    }
    ResumeThread(pi.hThread); CloseHandle(pi.hThread);
    while(WaitForSingleObject(pi.hProcess,500)==WAIT_TIMEOUT) AttachEngine(pi.dwProcessId,job,engine);
    AttachEngine(pi.dwProcessId,job,engine);
    CloseHandle(pi.hProcess); CloseHandle(job); ReleaseMutex(mutex); CloseHandle(mutex);
    /* The UI has exited. HuoChat's own "net stop" needs elevation and fails
       silently, so the engine (and its service registration) would survive and
       keep this folder locked. Ask the engine to exit so it can save its index,
       then release whatever is left. */
    RequestEngineExit(dir);
    { DWORD waited=0;
      while(waited<15000) {
          if(!EngineRunning(dir)) break;
          Sleep(250); waited+=250;
      } }
    StopEngineProcesses(dir);
    StopEngineService(dir);
    return 0;
}
