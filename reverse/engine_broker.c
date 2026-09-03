/* Compatibility entry point used by the original HuoChat UI. The engine's
   signed bytes stay untouched; all control commands are scoped to this copy. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "backend.h"
static DWORD ManageService(const BackendPaths *paths,LPCWSTR action) {
    BOOL install=!lstrcmpiW(action,L"-install-service"),remove=!lstrcmpiW(action,L"-uninstall-service");
    BOOL start=install || !lstrcmpiW(action,L"-start-service");
    SC_HANDLE manager=NULL,service=NULL;DWORD error=0,need=0,access=SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS;
    LPQUERY_SERVICE_CONFIGW config=NULL;WCHAR command[PATH_CAP+180],image[PATH_CAP];SERVICE_STATUS status={0};ULONGLONG deadline;
    manager=OpenSCManagerW(NULL,NULL,SC_MANAGER_CONNECT|(install ? SC_MANAGER_CREATE_SERVICE:0));
    if(!manager)return GetLastError();
    access|=start ? SERVICE_START:SERVICE_STOP;if(remove)access|=DELETE;
    service=OpenServiceW(manager,paths->service,access);
    if(!service && install && GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST) {
        StringCchPrintfW(command,PATH_CAP+180,L"\"%s\" -svc -svc-pipe-name \"%s\"",paths->exe,paths->pipe);
        service=CreateServiceW(manager,paths->service,paths->service,access,SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,command,NULL,NULL,NULL,NULL,NULL);
    }
    if(!service){error=GetLastError();if(remove && error==ERROR_SERVICE_DOES_NOT_EXIST)error=0;goto done;}
    QueryServiceConfigW(service,NULL,0,&need);
    if(!need || !(config=(LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),0,need)) ||
       !QueryServiceConfigW(service,config,need,&need)){error=GetLastError();goto done;}
    {
        LPCWSTR text=config->lpBinaryPathName,end;size_t length;
        if(!text){error=ERROR_INVALID_DATA;goto done;}
        if(*text==L'"'){text++;end=wcschr(text,L'"');}else{end=wcschr(text,L' ');if(!end)end=text+wcslen(text);}
        if(!end || (length=end-text)>=PATH_CAP){error=ERROR_INVALID_DATA;goto done;}
        CopyMemory(image,text,length*sizeof(WCHAR));image[length]=0;
        if(!SameBackendFile(image,paths->exe)){error=ERROR_ACCESS_DENIED;goto done;}
    }
    if(start) {
        if(!StartServiceW(service,0,NULL) && GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING){error=GetLastError();goto done;}
    } else if(!ControlService(service,SERVICE_CONTROL_STOP,&status) && GetLastError()!=ERROR_SERVICE_NOT_ACTIVE) {
        error=GetLastError();goto done;
    }
    deadline=GetTickCount64()+8000;
    while(QueryServiceStatus(service,&status) && status.dwCurrentState!=(start ? SERVICE_RUNNING:SERVICE_STOPPED) && GetTickCount64()<deadline)Sleep(50);
    if(status.dwCurrentState!=(start ? SERVICE_RUNNING:SERVICE_STOPPED)){error=ERROR_SERVICE_REQUEST_TIMEOUT;goto done;}
    if(remove && !DeleteService(service))error=GetLastError();
done:
    if(config)HeapFree(GetProcessHeap(),0,config);
    if(service)CloseServiceHandle(service);CloseServiceHandle(manager);return error;
}
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR args,int show) {
    BackendPaths paths;WCHAR command[4096],action[64]=L"";LPWSTR *argv;int argc,i;BOOL control=FALSE,service_control=FALSE;
    STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};DWORD code=0;(void)a;(void)b;(void)args;(void)show;
    if(!BackendFromModule(&paths,NULL) || !paths.modern)return ERROR_FILE_NOT_FOUND;
    argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return ERROR_INVALID_PARAMETER;
    for(i=1;i<argc;i++) {
        if(!lstrcmpiW(argv[i],L"-install-service") || !lstrcmpiW(argv[i],L"-uninstall-service") ||
           !lstrcmpiW(argv[i],L"-start-service") || !lstrcmpiW(argv[i],L"-stop-service")) {
            control=service_control=TRUE;StringCchCopyW(action,64,argv[i]);
        } else if(!lstrcmpiW(argv[i],L"-exit") || !lstrcmpiW(argv[i],L"-quit")) {
            control=TRUE;StringCchCopyW(action,64,argv[i]);
        } else if(!lstrcmpiW(argv[i],L"-startup") || !lstrcmpiW(argv[i],L"-hide")) {}
        else {LocalFree(argv);return ERROR_INVALID_PARAMETER;}
    }
    LocalFree(argv);
    JoinPath(log_path,PATH_CAP,paths.root,L"Data\\offline.log");
    if(!PrepareBackend(&paths))return GetLastError();
    if(service_control){code=ManageService(&paths,action);LogEvent(L"独立索引服务操作完成",code);return (int)code;}
    if(control)StringCchPrintfW(command,4096,L"\"%s\" -instance %s %s",paths.exe,paths.instance,action);
    else StringCchPrintfW(command,4096,L"\"%s\" -instance %s -config \"%s\" -db \"%s\" -safe-mode -startup",
        paths.exe,paths.instance,paths.config,paths.database);
    si.cb=sizeof(si);
    if(!CreateProcessW(paths.exe,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,paths.root,&si,&pi))return GetLastError();
    CloseHandle(pi.hThread);
    if(control) {
        if(WaitForSingleObject(pi.hProcess,15000)==WAIT_OBJECT_0)GetExitCodeProcess(pi.hProcess,&code);
        else code=ERROR_TIMEOUT;
    }
    CloseHandle(pi.hProcess);return (int)code;
}
