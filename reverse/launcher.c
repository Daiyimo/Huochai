#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include "portable.h"
#include "migration.h"
#include "startup.h"
#include "index_checkpoint.h"
#include "backend.h"

#ifndef HUOCHAT_LAUNCHER_MUTEX
#define HUOCHAT_LAUNCHER_MUTEX L"Local\\HuoChatOfflineLauncherV1"
#define HUOCHAT_READY_EVENT L"Local\\HuoChatOfflineLauncherReadyV2"
#endif
#ifndef HUOCHAT_STOP_EVENT
#define HUOCHAT_STOP_EVENT L"Local\\HuoChatOfflineLauncherStoppingV1"
#endif

/* Discovery stops as soon as the engine is known. Wait on lifecycle handles
   and checkpoint deadlines; a restarted engine is discovered again. */
static HANDLE FindEngine(HANDLE job,LPCWSTR expected) {
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process,found=NULL; WCHAR image[PATH_CAP]; DWORD count,session,own_session;
    if(!ProcessIdToSessionId(GetCurrentProcessId(),&own_session)) return NULL;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return NULL;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(lstrcmpiW(entry.szExeFile,wcsrchr(expected,L'\\')+1) ||
           !ProcessIdToSessionId(entry.th32ProcessID,&session) || session!=own_session) continue;
        process=OpenProcess(SYNCHRONIZE|PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!process) process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!process) continue;
        count=PATH_CAP;
        if(QueryFullProcessImageNameW(process,0,image,&count) && SameBackendFile(image,expected)) {
            if(!AssignProcessToJobObject(job,process)) LogEvent(L"无法将搜索引擎加入退出清理作业",GetLastError());
            found=process; break;
        }
        CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
    return found;
}

static void WaitForUi(PROCESS_INFORMATION *ui,HANDLE job,LPCWSTR expected,HANDLE stopping,LPCWSTR dir) {
    HANDLE engine=NULL,handles[3]; DWORD result,timeout,started=GetTickCount();IndexCheckpoint checkpoint={0};
    for(;;) {
        if(WaitForSingleObject(ui->hProcess,0)==WAIT_OBJECT_0 || WaitForSingleObject(stopping,0)==WAIT_OBJECT_0)break;
        if(!engine) {
            engine=FindEngine(job,expected);
            if(engine) {
                LogEvent(L"搜索引擎已接管，停止周期性进程扫描",0);
                InitCheckpoint(&checkpoint,engine,dir);
            }
        }
        handles[0]=ui->hProcess; handles[1]=stopping; handles[2]=engine;
        timeout=engine ? TickCheckpoint(&checkpoint,engine,stopping) : GetTickCount()-started<10000 ? 500:5000;
        result=WaitForMultipleObjects(engine ? 3:2,handles,FALSE,timeout);
        if(result==WAIT_OBJECT_0 || result==WAIT_OBJECT_0+1 || result==WAIT_FAILED) break;
        if(engine && result==WAIT_OBJECT_0+2) {
            CloseHandle(engine); engine=NULL; started=GetTickCount();
            LogEvent(L"搜索引擎已退出，等待可能的重启",0);
        }
    }
    if(engine) CloseHandle(engine);
}

/* SERVICE_DELETE is 0x10000; winsvc.h hides it under WIN32_LEAN_AND_MEAN. */
#define SVC_DELETE 0x00010000L

static BOOL ServiceBelongsToDir(SC_HANDLE scm,LPCWSTR selfdir) {
    SC_HANDLE svc=NULL; BOOL owned=FALSE;
    DWORD need=0; LPQUERY_SERVICE_CONFIGW cfg=NULL; WCHAR expected[PATH_CAP]; size_t length;
    BackendPaths backend;if(!BackendFromDirectory(&backend,selfdir))return FALSE;
    svc=OpenServiceW(scm,backend.service,SERVICE_QUERY_CONFIG);
    if(!svc) return FALSE;
    need=0;
    QueryServiceConfigW(svc,NULL,0,&need);
    if(need) cfg=(LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),0,need);
    if(cfg && QueryServiceConfigW(svc,cfg,need,&need) && cfg->lpBinaryPathName) {
        /* The path may be quoted; skip the quote before comparing. */
        LPCWSTR bin=cfg->lpBinaryPathName;
        if(*bin==L'"') ++bin;
        if(SUCCEEDED(StringCchCopyW(expected,PATH_CAP,backend.exe))) {
            length=wcslen(expected);
            owned=!_wcsnicmp(bin,expected,length) && (bin[length]==0 || bin[length]==L'"' || bin[length]==L' ');
        }
    }
    if(cfg) HeapFree(GetProcessHeap(),0,cfg);
    CloseServiceHandle(svc);
    return owned;
}

static void StopEngineService(LPCWSTR selfdir) {
    SC_HANDLE scm=NULL,svc=NULL; SERVICE_STATUS st={0}; BOOL requested=FALSE;
    BackendPaths backend;if(!BackendFromDirectory(&backend,selfdir))return;
    scm=OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT);
    if(!scm) return;
    if(!ServiceBelongsToDir(scm,selfdir)) { CloseServiceHandle(scm); return; }
    /* Request only the rights needed for each operation. Standard users may
       have permission to stop this service but not DELETE permission; asking
       for both on one handle made OpenService fail and skipped all cleanup. */
    svc=OpenServiceW(scm,backend.service,SERVICE_QUERY_STATUS|SERVICE_STOP);
    if(svc) {
        requested=ControlService(svc,SERVICE_CONTROL_STOP,&st) || GetLastError()==ERROR_SERVICE_NOT_ACTIVE;
        if(!requested) LogEvent(L"停止本程序的 Everything 服务失败",GetLastError());
        CloseServiceHandle(svc);
    } else LogEvent(L"没有停止本程序 Everything 服务的权限",GetLastError());
    if(!requested) { CloseServiceHandle(scm); return; }
    svc=OpenServiceW(scm,backend.service,SVC_DELETE);
    if(svc) {
        if(!DeleteService(svc)) LogEvent(L"删除本程序的 Everything 服务注册失败",GetLastError());
        CloseServiceHandle(svc);
    } else LogEvent(L"没有删除本程序 Everything 服务注册的权限",GetLastError());
    CloseServiceHandle(scm);
}

/* Take one snapshot at shutdown, then wait on the actual process handles.
   The directory test never touches a separately installed Everything. */
static DWORD CollectEngines(LPCWSTR selfdir,HANDLE *handles,DWORD capacity) {
    PROCESSENTRY32W entry={0}; HANDLE snapshot,process; WCHAR image[PATH_CAP],expected[PATH_CAP]; DWORD count,total=0;
    BackendPaths backend;if(!BackendFromDirectory(&backend,selfdir))return 0;
    StringCchCopyW(expected,PATH_CAP,backend.exe);
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) return 0;
    entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry)) do {
        if(lstrcmpiW(entry.szExeFile,wcsrchr(expected,L'\\')+1)) continue;
        process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE,FALSE,entry.th32ProcessID);
        if(!process) {
            process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
            if(!process) continue;
        }
        count=PATH_CAP;
        if(QueryFullProcessImageNameW(process,0,image,&count) && SameBackendFile(image,expected) && total<capacity)
            handles[total++]=process;
        else CloseHandle(process);
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
    return total;
}

static BOOL ShutdownEngines(LPCWSTR dir) {
    HANDLE engines[MAXIMUM_WAIT_OBJECTS]; DWORD count,i; BOOL stopped=TRUE;
    count=CollectEngines(dir,engines,MAXIMUM_WAIT_OBJECTS);
    /* User-requested cancellation: do not send -exit, which asks the engine
       to flush a potentially large or unfinished index. Keep the last cache;
       the engine loads/updates it, or rebuilds a missing cache, next launch. */
    for(i=0;i<count;i++) {
        if(WaitForSingleObject(engines[i],0)!=WAIT_OBJECT_0) {
            if(!TerminateProcess(engines[i],0)) {
                LogEvent(L"残留搜索引擎无法结束，请检查进程权限",GetLastError());stopped=FALSE;
            }
        }
    }
    if(count && WaitForMultipleObjects(count,engines,TRUE,1500)!=WAIT_OBJECT_0) stopped=FALSE;
    for(i=0;i<count;i++) {
        CloseHandle(engines[i]);
    }
    return stopped;
}

int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR args,int show) {
    BackendPaths backend;
    WCHAR path[PATH_CAP],command[PATH_CAP+32],engine[PATH_CAP],dir[PATH_CAP],state[PATH_CAP],data[PATH_CAP],temp[PATH_CAP],index[PATH_CAP],probe[PATH_CAP];
    DWORD n,error,exitcode=0; int result=0; HANDLE job=NULL,mutex=NULL,ready,stopping=NULL;
    BOOL engines_stopped;
    BOOL prepare_only=!strcmp(args,"--prepare"),startup=!strcmp(args,"-s"); LONG startup_status;
    STARTUPINFOW si={0}; PROCESS_INFORMATION pi={0}; JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
    (void)instance;(void)previous;(void)args;(void)show;
    n=GetModuleFileNameW(NULL,path,PATH_CAP);
    if(!n || n>=PATH_CAP-64) { ReportFailure(L"程序路径过长，请移动到较短的本地路径。",ERROR_FILENAME_EXCED_RANGE); return 2; }
    while(n && path[n-1]!=L'\\') --n;
    path[n]=0; StringCchCopyW(dir,PATH_CAP,path);
    JoinPath(log_path,PATH_CAP,dir,L"Data\\offline.log");
    mutex=CreateMutexW(NULL,TRUE,HUOCHAT_LAUNCHER_MUTEX);
    error=GetLastError();
    if(!mutex) { if(!prepare_only) ReportFailure(L"无法初始化程序运行锁。",error); return 1; }
    if(error==ERROR_ALREADY_EXISTS) { CloseHandle(mutex); return 1; }
    if(!PrepareData(dir)) {
        if(!prepare_only) ReportFailure(L"数据整理未完成。请退出火柴和由它启动的程序；重名数据不会被覆盖。",GetLastError());
        result=21; goto finish;
    }
    if(prepare_only) goto finish;
    stopping=CreateEventW(NULL,TRUE,FALSE,HUOCHAT_STOP_EVENT);
    if(!stopping) { ReportFailure(L"无法初始化退出通知。",GetLastError());result=3;goto finish; }
    ResetEvent(stopping);
    ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,HUOCHAT_READY_EVENT);
    if(ready) { SetEvent(ready); CloseHandle(ready); }
    LogEvent(L"火柴启动",0);
    if(!JoinPath(data,PATH_CAP,dir,L"Data\\") ||
       !JoinPath(state,PATH_CAP,dir,L"Data\\User") || !EnsureDirectory(state) ||
       !JoinPath(index,PATH_CAP,dir,L"Data\\Index") || !EnsureDirectory(index) ||
       !JoinPath(temp,PATH_CAP,dir,L"Data\\Temp") || !EnsureDirectory(temp) ||
       !GetTempFileNameW(temp,L"hcw",0,probe)) {
        ReportFailure(L"无法写入数据目录。请检查目录权限和磁盘空间。",GetLastError()); result=2; goto finish;
    }
    DeleteFileW(probe);
    if(!BackendFromDirectory(&backend,dir) || !(backend.modern ? PrepareBackend(&backend):UpdateConfiguration(data,index))) {
        ReportFailure(L"无法准备搜索引擎配置。请检查 Data 内索引配置及 Engine 目录的占用和权限。",GetLastError()); result=2; goto finish;
    }
    startup_status=ReconcileStartup(dir);
    if(startup_status!=ERROR_SUCCESS) LogEvent(L"开机启动入口更新失败，将在下次启动时重试",startup_status);
    /* Preserve the caller's environment for external applications. HuoChat's
       own AppData/temp APIs are redirected inside hcg.dll, not inherited by
       independently running programs such as WeGame. */
    JoinPath(path,PATH_CAP,dir,L"HuoChat.exe"); StringCchCopyW(engine,PATH_CAP,backend.exe);
    StringCchPrintfW(command,PATH_CAP+32,L"\"%s\"%s",path,startup ? L" -s":L"");
    job=CreateJobObjectW(NULL,NULL);
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if(!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) {
        ReportFailure(L"无法初始化进程退出清理。",GetLastError()); result=3; goto finish;
    }
    si.cb=sizeof(si);
    if(!CreateProcessW(path,command,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,dir,&si,&pi)) {
        ReportFailure(L"火柴主程序无法启动。请重新运行外层单文件以校验并修复程序文件。",GetLastError()); result=4; goto finish;
    }
    if(!AssignProcessToJobObject(job,pi.hProcess)) {
        error=GetLastError(); TerminateProcess(pi.hProcess,5); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        ReportFailure(L"无法接管火柴主进程。",error); result=5; goto finish;
    }
    if(ResumeThread(pi.hThread)==(DWORD)-1) {
        error=GetLastError(); TerminateProcess(pi.hProcess,5); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        ReportFailure(L"无法恢复火柴主进程。",error); result=5; goto finish;
    }
    CloseHandle(pi.hThread);
    WaitForUi(&pi,job,engine,stopping,dir);
    SetEvent(stopping);
    LogEvent(L"已收到退出请求，取消本次索引工作",0);
    /* Notify the service manager before terminating an owned service process,
       so intentional shutdown is not mistaken for a recoverable crash. */
    StopEngineService(dir);
    ShutdownEngines(dir);
    /* Preferences were synchronously saved before the UI signalled stopping.
       Allow native note/history teardown to finish, without waiting for scans. */
    if(WaitForSingleObject(pi.hProcess,5000)!=WAIT_OBJECT_0) {
        LogEvent(L"主程序退出清理超时，结束已保存设置的主进程",ERROR_TIMEOUT);
        TerminateProcess(pi.hProcess,0);WaitForSingleObject(pi.hProcess,1000);
    }
    GetExitCodeProcess(pi.hProcess,&exitcode); CloseHandle(pi.hProcess);
    /* Catch a helper launched by native teardown after the first snapshot. */
    engines_stopped=ShutdownEngines(dir);
    CloseHandle(job);
    if(!engines_stopped) {
        LogEvent(L"部分索引进程未能结束，请检查进程权限",ERROR_ACCESS_DENIED);
    }
    job=NULL;
    if(exitcode) { ReportFailure(L"火柴主程序异常退出。配置和便签目录已保留。",exitcode); result=6; }
    LogEvent(L"火柴退出流程已结束",0);
finish:
    if(job) CloseHandle(job);
    if(stopping) CloseHandle(stopping);
    ReleaseMutex(mutex); CloseHandle(mutex);
    return result;
}
