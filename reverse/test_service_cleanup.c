/* Service permissions are simulated; this harness never opens a real service. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
/* engine_broker.c is included further down, after the fake SCM below. Pull the
   header in now so the DELETE access right is spelled the same way here and in
   the code under test. */
#include "backend.h"
static LPCWSTR service_path,broker_path;
static int denied_stop,denied_control,denied_delete,broker_mode,service_running,stops,deletes;
static DWORD open_access[8];
static int open_calls;
static SC_HANDLE WINAPI FakeManager(LPCWSTR a,LPCWSTR b,DWORD access) {(void)a;(void)b;(void)access;return (SC_HANDLE)1;}
static SC_HANDLE WINAPI FakeOpen(SC_HANDLE manager,LPCWSTR name,DWORD access) {
    (void)manager;(void)name;
    if(open_calls<8) open_access[open_calls++]=access;
    if((access&SERVICE_STOP) && denied_stop) { SetLastError(ERROR_ACCESS_DENIED);return NULL; }
    if((access&SVC_DELETE) && denied_delete) { SetLastError(ERROR_ACCESS_DENIED);return NULL; }
    return (SC_HANDLE)2;
}
static BOOL WINAPI FakeQuery(SC_HANDLE handle,LPQUERY_SERVICE_CONFIGW config,DWORD bytes,LPDWORD needed) {
    (void)handle;*needed=sizeof(*config);
    if(bytes<*needed) { SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE; }
    ZeroMemory(config,sizeof(*config));
    config->lpBinaryPathName=(LPWSTR)(broker_mode ? broker_path:service_path);
    return TRUE;
}
static BOOL WINAPI FakeControl(SC_HANDLE handle,DWORD control,LPSERVICE_STATUS status) {
    (void)handle;(void)control;(void)status;stops++;
    if(denied_control) { SetLastError(ERROR_ACCESS_DENIED);return FALSE; }return TRUE;
}
static BOOL WINAPI FakeStatus(SC_HANDLE handle,LPSERVICE_STATUS status) {
    (void)handle;
    status->dwCurrentState=service_running ? SERVICE_RUNNING:SERVICE_STOPPED;
    return TRUE;
}
static BOOL WINAPI FakeStart(SC_HANDLE handle,DWORD argc,LPWSTR *argv) {
    (void)handle;(void)argc;(void)argv;return TRUE;
}
static BOOL WINAPI FakeDelete(SC_HANDLE handle) {(void)handle;deletes++;return TRUE;}
static BOOL WINAPI FakeClose(SC_HANDLE handle) {(void)handle;return TRUE;}
static SC_HANDLE WINAPI FakeCreate(SC_HANDLE manager,LPCWSTR name,LPCWSTR display,DWORD access,
    DWORD type,DWORD start,DWORD error,LPCWSTR image,LPCWSTR group,LPDWORD tag,LPCWSTR deps,
    LPCWSTR account,LPCWSTR password) {
    (void)manager;(void)name;(void)display;(void)access;(void)type;(void)start;(void)error;
    (void)image;(void)group;(void)tag;(void)deps;(void)account;(void)password;
    return (SC_HANDLE)3;
}
/* engine_broker.c resolves its own command line through CommandLineToArgvW,
   which lives in shell32. The harness links shell32 for that one import and
   never calls the broker's entry point, so Renaming the declaration to a local
   stub is not needed -- and renaming it would also rename shellapi.h's own
   declaration once that header is pulled in behind WIN32_LEAN_AND_MEAN. */
#define OpenSCManagerW FakeManager
#define OpenServiceW FakeOpen
#define QueryServiceConfigW FakeQuery
#define QueryServiceStatus FakeStatus
#define ControlService FakeControl
#define StartServiceW FakeStart
#define CreateServiceW FakeCreate
#define DeleteService FakeDelete
#define CloseServiceHandle FakeClose
#define WinMain UnusedLauncherMain
#include "launcher.c"
#undef WinMain
/* hc_engine.exe links shell32 for its own command line; redirect just that one. */
#define WinMain UnusedBrokerMain
#include "engine_broker.c"
#define CHECK(x) do { if(!(x)) { printf("Service test failed %d\n",__LINE__);return 1; } } while(0)
int main(void) {
    BackendPaths broker; DWORD code;
    service_path=L"\"C:\\owned\\hc_engine.exe\" -svc";
    CHECK(ServiceBelongsToDir((SC_HANDLE)1,L"C:\\owned\\"));
    StopEngineService(L"C:\\owned\\");CHECK(stops==1 && deletes==1);
    stops=deletes=0;denied_stop=1;StopEngineService(L"C:\\owned\\");CHECK(stops==0 && deletes==0);
    denied_stop=0;denied_control=1;StopEngineService(L"C:\\owned\\");CHECK(stops==1 && deletes==0);
    stops=0;denied_control=0;
    service_path=L"C:\\owned\\hc_engine.exe.bak -svc";
    StopEngineService(L"C:\\owned\\");CHECK(stops==0 && deletes==0);
    service_path=L"\"C:\\owned-other\\hc_engine.exe\" -svc";
    StopEngineService(L"C:\\owned\\");CHECK(stops==0 && deletes==0);
    /* The broker must not fold DELETE into the handle it stops the service on. */
    ZeroMemory(&broker,sizeof(broker));
    broker.modern=TRUE;
    StringCchCopyW(broker.exe,PATH_CAP,L"C:\\owned\\Engine\\Everything.exe");
    StringCchPrintfW(broker.instance,64,L"HuoChat15-0123456789abcdef");
    StringCchCopyW(broker.service,64,broker.instance);
    StringCchPrintfW(broker.pipe,128,L"\\\\.\\PIPE\\%s",broker.instance);
    broker_path=L"\"C:\\owned\\Engine\\Everything.exe\" -svc -svc-pipe-name \"\\\\.\\PIPE\\HuoChat15-0123456789abcdef\"";
    denied_delete=1;broker_mode=1;stops=deletes=0;open_calls=0;
    code=ManageService(&broker,L"-uninstall-service");
    /* Stop allowed, delete refused: the stop still happened, and it is reported. */
    CHECK(code==ERROR_ACCESS_DENIED && stops==1 && deletes==0 && open_calls==2);
    CHECK((open_access[0]&SERVICE_STOP) && !(open_access[0]&SVC_DELETE));
    CHECK((open_access[1]&SVC_DELETE) && !(open_access[1]&SERVICE_STOP));
    denied_delete=0;stops=deletes=0;open_calls=0;code=ManageService(&broker,L"-uninstall-service");
    CHECK(code==0 && stops==1 && deletes==1 && open_calls==2);
    code=ManageService(&broker,L"-stop-service");
    CHECK(code==0 && stops==2 && deletes==1 && open_calls==3);
    broker_path=L"\"C:\\other\\Engine\\Everything.exe\" -svc";
    stops=deletes=0;open_calls=0;code=ManageService(&broker,L"-uninstall-service");
    CHECK(code==ERROR_ACCESS_DENIED && stops==0 && deletes==0 && open_calls==1);
    broker_mode=0;
    puts("Service cleanup passed: exact image path, foreign service preserved, denied stop never deletes registration, denied delete still stops.");return 0;
}
