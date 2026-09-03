/* Minimal UI fixture: starts the real engine in a unique test instance. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#ifndef HUOCHAT_STOP_EVENT
#error Test-specific stop event required
#endif
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR args,int show) {
    WCHAR name[128],command[2048];STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};
    HANDLE file,event;DWORD wrote;CHAR pid[32];(void)a;(void)b;(void)args;(void)show;
    if(!GetEnvironmentVariableW(L"HUOCHAT_TEST_INSTANCE",name,128))return 2;
    StringCchPrintfW(command,2048,L"hc_engine.exe -instance %s -rescan-all",name);si.cb=sizeof(si);
    if(!CreateProcessW(L"hc_engine.exe",command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi))return 3;
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    StringCchPrintfA(pid,32,"%lu",pi.dwProcessId);
    file=CreateFileW(L"engine.pid",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return 4;WriteFile(file,pid,lstrlenA(pid),&wrote,NULL);CloseHandle(file);
    while(GetFileAttributesW(L"test-stop")==INVALID_FILE_ATTRIBUTES)Sleep(25);
    event=OpenEventW(EVENT_MODIFY_STATE,FALSE,HUOCHAT_STOP_EVENT);
    if(event){SetEvent(event);CloseHandle(event);}return 0;
}
