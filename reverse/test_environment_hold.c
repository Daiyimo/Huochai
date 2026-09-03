/* A separate external application retains cache handles while the production
   launcher exits. Its executable and working directory are outside HuoChat. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>
#ifndef HUOCHAT_STOP_EVENT
#error Isolated test event required
#endif
typedef BOOL(WINAPI *SPAWN)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef DWORD(WINAPI *TEMPPATH)(DWORD,LPWSTR);
static BOOL WriteText(LPCWSTR path,LPCSTR text) {
    DWORD wrote;BOOL ok;HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    ok=WriteFile(file,text,(DWORD)strlen(text),&wrote,NULL);CloseHandle(file);return ok;
}
int WINAPI WinMain(HINSTANCE a,HINSTANCE b,LPSTR args,int show) {
    WCHAR root[1024],path[1200],ready[1200],stop[1200];DWORD count,i;ULONGLONG deadline=GetTickCount64()+60000;
    (void)a;(void)b;(void)show;
    if(!GetEnvironmentVariableW(L"HC_HOLDER_READY",ready,1200) || !GetEnvironmentVariableW(L"HC_HOLDER_STOP",stop,1200))return 2;
    if(!strcmp(args,"--worker")) {
        const WCHAR *variables[]={L"APPDATA",L"LOCALAPPDATA",L"TEMP",L"TMP"};HANDLE files[4];CHAR pid[32];
        for(i=0;i<4;i++) {
            if(!GetEnvironmentVariableW(variables[i],root,1024))return 3;
            StringCchPrintfW(path,1200,L"%s\\cache-holder-%lu.dat",root,i);
            files[i]=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL);
            if(files[i]==INVALID_HANDLE_VALUE)return 4;
        }
        StringCchPrintfA(pid,32,"%lu",GetCurrentProcessId());if(!WriteText(ready,pid))return 5;
        while(GetFileAttributesW(stop)==INVALID_FILE_ATTRIBUTES && GetTickCount64()<deadline)Sleep(20);
        for(i=0;i<4;i++)CloseHandle(files[i]);return 0;
    } else {
        HMODULE guard=LoadLibraryW(L"hcg.dll");SPAWN spawn;TEMPPATH get_temp;
        WCHAR external[1024],directory[1024],command[1200],expected[1200],actual[1200];
        STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};HANDLE event;
        if(!guard)return 6;spawn=(SPAWN)GetProcAddress(guard,"CreateProcessW");get_temp=(TEMPPATH)GetProcAddress(guard,"GetTempPathW");
        if(!spawn || !get_temp || !GetEnvironmentVariableW(L"HC_HOLDER_EXE",external,1024))return 7;
        StringCchCopyW(directory,1024,external);*wcsrchr(directory,L'\\')=0;
        count=GetModuleFileNameW(NULL,root,1024);if(!count)return 8;*wcsrchr(root,L'\\')=0;
        StringCchPrintfW(expected,1200,L"%s\\Data\\Temp\\",root);
        if(!get_temp(1200,actual) || lstrcmpiW(actual,expected))return 9;
        StringCchPrintfW(command,1200,L"\"%s\" --worker",external);si.cb=sizeof(si);
        if(!spawn(external,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,directory,&si,&pi))return 10;
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        while(GetFileAttributesW(ready)==INVALID_FILE_ATTRIBUTES && GetTickCount64()<deadline)Sleep(20);
        StringCchPrintfW(path,1200,L"%s\\ui.ready",root);if(!WriteText(path,"ready"))return 11;
        StringCchPrintfW(path,1200,L"%s\\test-stop",root);
        while(GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES && GetTickCount64()<deadline)Sleep(20);
        event=OpenEventW(EVENT_MODIFY_STATE,FALSE,HUOCHAT_STOP_EVENT);
        if(event){SetEvent(event);CloseHandle(event);}FreeLibrary(guard);return 0;
    }
}
