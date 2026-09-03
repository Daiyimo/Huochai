#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef HUOCHAT_STOP_EVENT
#error Test-specific event required
#endif
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR args,int show) {
    STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};WCHAR command[]=L"hc_engine.exe";HANDLE event;
    (void)a;(void)b;(void)args;(void)show;si.cb=sizeof(si);
    if(!CreateProcessW(L"hc_engine.exe",command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi))return 3;
    CloseHandle(pi.hThread);WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hProcess);
    while(GetFileAttributesW(L"test-stop")==INVALID_FILE_ATTRIBUTES)Sleep(25);
    event=OpenEventW(EVENT_MODIFY_STATE,FALSE,HUOCHAT_STOP_EVENT);
    if(event){SetEvent(event);CloseHandle(event);}return 0;
}
