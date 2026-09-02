/* Service permissions are simulated; this harness never opens a real service. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
static LPCWSTR service_path;
static int denied_stop,denied_control,stops,deletes;
static SC_HANDLE WINAPI FakeManager(LPCWSTR a,LPCWSTR b,DWORD access) {(void)a;(void)b;(void)access;return (SC_HANDLE)1;}
static SC_HANDLE WINAPI FakeOpen(SC_HANDLE manager,LPCWSTR name,DWORD access) {
    (void)manager;(void)name;
    if((access&SERVICE_STOP) && denied_stop) { SetLastError(ERROR_ACCESS_DENIED);return NULL; }
    return (SC_HANDLE)2;
}
static BOOL WINAPI FakeQuery(SC_HANDLE handle,LPQUERY_SERVICE_CONFIGW config,DWORD bytes,LPDWORD needed) {
    (void)handle;*needed=sizeof(*config);
    if(bytes<*needed) { SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE; }
    ZeroMemory(config,sizeof(*config));config->lpBinaryPathName=(LPWSTR)service_path;return TRUE;
}
static BOOL WINAPI FakeControl(SC_HANDLE handle,DWORD control,LPSERVICE_STATUS status) {
    (void)handle;(void)control;(void)status;stops++;
    if(denied_control) { SetLastError(ERROR_ACCESS_DENIED);return FALSE; }return TRUE;
}
static BOOL WINAPI FakeDelete(SC_HANDLE handle) {(void)handle;deletes++;return TRUE;}
static BOOL WINAPI FakeClose(SC_HANDLE handle) {(void)handle;return TRUE;}
#define OpenSCManagerW FakeManager
#define OpenServiceW FakeOpen
#define QueryServiceConfigW FakeQuery
#define ControlService FakeControl
#define DeleteService FakeDelete
#define CloseServiceHandle FakeClose
#define WinMain UnusedLauncherMain
#include "launcher.c"
#define CHECK(x) do { if(!(x)) { printf("Service test failed %d\n",__LINE__);return 1; } } while(0)
int main(void) {
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
    puts("Service cleanup passed: exact image path, foreign service preserved, denied stop never deletes registration.");return 0;
}
