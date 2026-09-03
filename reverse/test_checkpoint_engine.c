/* A slow SAVE_DB handler must not hold up production launcher cancellation. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static LRESULT CALLBACK Receive(HWND window,UINT message,WPARAM w,LPARAM l) {
    if(message==WM_USER && w==401)return 1;
    if(message==WM_USER && w==407) {
        HANDLE file=CreateFileW(L"save-requested",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);
        if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
        Sleep(16000);
        return 1;
    }
    return DefWindowProcW(window,message,w,l);
}
int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR args,int show) {
    WNDCLASSW wc={0};MSG message;
    (void)previous;(void)args;(void)show;
    wc.lpfnWndProc=Receive;wc.hInstance=instance;
    wc.lpszClassName=L"EVERYTHING_TASKBAR_NOTIFICATION_CHECKPOINT_TEST";
    if(!RegisterClassW(&wc) || !CreateWindowW(wc.lpszClassName,L"",0,0,0,0,0,NULL,NULL,instance,NULL))return 1;
    while(GetMessageW(&message,NULL,0,0)>0)DispatchMessageW(&message);
    return 0;
}
