/* Spawn real local children through each supported entry; no network or UI. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>
#define CHECK(x) do { if(!(x)) { printf("Environment test failed %d (error=%lu)\n",__LINE__,GetLastError()); return 1; } } while(0)
typedef BOOL (WINAPI *CPW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CPA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *SEW)(SHELLEXECUTEINFOW*);
typedef BOOL (WINAPI *SEA)(SHELLEXECUTEINFOA*);
typedef HINSTANCE (WINAPI *SW)(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
typedef HINSTANCE (WINAPI *SA)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);
typedef UINT (WINAPI *EXEC)(LPCSTR,UINT);

int wmain(int argc,WCHAR **argv) {
    const WCHAR *names[]={L"APPDATA",L"LOCALAPPDATA",L"TEMP",L"TMP"};
    WCHAR self[1024],dir[1024],path[1200],temp[1200],args[1400],command[2500],value[1024];
    CHAR appa[4096],argsa[5600],cmda[10000],utf8[4096]; DWORD n,i,j; HANDLE file; HMODULE guard;
    if(argc==3 && !lstrcmpW(argv[1],L"--child")) {
        CHECK(SUCCEEDED(StringCchPrintfW(temp,1200,L"%s.part",argv[2])));
        file=CreateFileW(temp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);CHECK(file!=INVALID_HANDLE_VALUE);
        for(i=0;i<4;i++) {
            CHECK(GetEnvironmentVariableW(names[i],value,1024));
            j=WideCharToMultiByte(CP_UTF8,0,value,-1,utf8,sizeof(utf8),NULL,NULL);CHECK(j);
            CHECK(WriteFile(file,utf8,j-1,&n,NULL));CHECK(WriteFile(file,"\n",1,&n,NULL));
        }
        CloseHandle(file);CHECK(MoveFileExW(temp,argv[2],MOVEFILE_REPLACE_EXISTING));return 0;
    }
    n=GetModuleFileNameW(NULL,self,1024);CHECK(n && n<1024);StringCchCopyW(dir,1024,self);
    while(n && dir[n-1]!=L'\\') n--;dir[n]=0;
    guard=LoadLibraryW(L"hcg.dll");CHECK(guard);
    WideCharToMultiByte(CP_ACP,0,self,-1,appa,sizeof(appa),NULL,NULL);
    for(i=0;i<7;i++) {
        PROCESS_INFORMATION pi={0};STARTUPINFOW sw={0};STARTUPINFOA sa={0};
        SHELLEXECUTEINFOW ew={0};SHELLEXECUTEINFOA ea={0};DWORD deadline;
        StringCchPrintfW(path,1200,L"%senv-child-%lu.txt",dir,i);
        StringCchPrintfW(args,1400,L"--child \"%s\"",path);
        StringCchPrintfW(command,2500,L"\"%s\" %s",self,args);
        WideCharToMultiByte(CP_ACP,0,args,-1,argsa,sizeof(argsa),NULL,NULL);
        WideCharToMultiByte(CP_ACP,0,command,-1,cmda,sizeof(cmda),NULL,NULL);
        DeleteFileW(path);
        switch(i) {
        case 0: sw.cb=sizeof(sw);CHECK(((CPW)GetProcAddress(guard,"CreateProcessW"))(self,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,dir,&sw,&pi));break;
        case 1: sa.cb=sizeof(sa);CHECK(((CPA)GetProcAddress(guard,"CreateProcessA"))(appa,cmda,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&sa,&pi));break;
        case 2: ew.cbSize=sizeof(ew);ew.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI;ew.lpFile=self;ew.lpParameters=args;ew.nShow=SW_HIDE;
            CHECK(((SEW)GetProcAddress(guard,"ShellExecuteExW"))(&ew));pi.hProcess=ew.hProcess;break;
        case 3: ea.cbSize=sizeof(ea);ea.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI;ea.lpFile=appa;ea.lpParameters=argsa;ea.nShow=SW_HIDE;
            CHECK(((SEA)GetProcAddress(guard,"ShellExecuteExA"))(&ea));pi.hProcess=ea.hProcess;break;
        case 4: CHECK((INT_PTR)((SW)GetProcAddress(guard,"ShellExecuteW"))(NULL,L"open",self,args,NULL,SW_HIDE)>32);break;
        case 5: CHECK((INT_PTR)((SA)GetProcAddress(guard,"ShellExecuteA"))(NULL,"open",appa,argsa,NULL,SW_HIDE)>32);break;
        case 6: CHECK(((EXEC)GetProcAddress(guard,"WinExec"))(cmda,SW_HIDE)>31);break;
        }
        if(pi.hThread) CloseHandle(pi.hThread);
        if(pi.hProcess) { CHECK(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0);CloseHandle(pi.hProcess); }
        deadline=GetTickCount();while(GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES && GetTickCount()-deadline<10000) Sleep(20);
        CHECK(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES);
    }
    FreeLibrary(guard);return 0;
}
