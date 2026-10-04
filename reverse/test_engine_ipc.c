/* Test-only IPC v1 query, selected by exact PID, including named instances.
   Wire layout and command numbers follow the public Everything SDK. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
static DWORD target_pid,total;
static HWND target;
static BOOL received;
static BOOL CALLBACK Locate(HWND hwnd,LPARAM unused) {
    DWORD pid;WCHAR name[128];(void)unused;
    GetWindowThreadProcessId(hwnd,&pid);
    if(pid==target_pid && GetClassNameW(hwnd,name,128) && !wcsncmp(name,L"EVERYTHING_TASKBAR_NOTIFICATION",wcslen(L"EVERYTHING_TASKBAR_NOTIFICATION"))) {target=hwnd;return FALSE;}
    return TRUE;
}
static LRESULT CALLBACK Reply(HWND hwnd,UINT message,WPARAM w,LPARAM l) {
    if(message==WM_COPYDATA) {
        COPYDATASTRUCT *data=(COPYDATASTRUCT*)l;
        if(data->dwData==17 && data->cbData>=28) {
            DWORD *header=(DWORD*)data->lpData;
            total=header[2];received=TRUE;return TRUE;
        }
    }
    return DefWindowProcW(hwnd,message,w,l);
}
int wmain(int argc,WCHAR **argv) {
    WNDCLASSW wc={0};HWND reply;MSG msg;COPYDATASTRUCT copy={0};DWORD_PTR response=0;ULONGLONG begin;
    struct {DWORD hwnd,id,flags,offset,max;WCHAR text[2048];} query={0};
    if(argc<3)return 2;target_pid=wcstoul(argv[1],NULL,10);EnumWindows(Locate,0);if(!target)return 3;
    if(!SendMessageTimeoutW(target,WM_USER,401,0,SMTO_ABORTIFHUNG,500,&response) || !response)return 4;
    wc.lpfnWndProc=Reply;wc.hInstance=GetModuleHandleW(NULL);wc.lpszClassName=L"HuoChatQueryRegression";
    if(!RegisterClassW(&wc))return 5;reply=CreateWindowW(wc.lpszClassName,L"",0,0,0,0,0,NULL,NULL,wc.hInstance,NULL);if(!reply)return 6;
    query.hwnd=(DWORD)(ULONG_PTR)reply;query.id=17;query.max=10;
    if(FAILED(StringCchCopyW(query.text,2048,argv[2])))return 7;
    copy.dwData=2;copy.cbData=20+(lstrlenW(query.text)+1)*2;copy.lpData=&query;
    if(!SendMessageTimeoutW(target,WM_COPYDATA,(WPARAM)reply,(LPARAM)&copy,SMTO_ABORTIFHUNG,1000,&response) || !response)return 8;
    begin=GetTickCount64();while(!received && GetTickCount64()-begin<5000) {
        while(PeekMessageW(&msg,NULL,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}Sleep(5);
    }
    DestroyWindow(reply);if(!received)return 9;printf("%lu\n",total);return 0;
}
