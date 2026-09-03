/* Real filesystem and shell calls through the packaged guard. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <strsafe.h>
typedef DWORD (WINAPI *ATTR)(LPCWSTR);
typedef HANDLE (WINAPI *OPEN)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE (WINAPI *FIND)(LPCWSTR,LPWIN32_FIND_DATAW);
typedef BOOL (WINAPI *SHELL)(SHELLEXECUTEINFOW *);
typedef DWORD (WINAPI *ATTRA)(LPCSTR);
typedef HANDLE (WINAPI *OPENA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE (WINAPI *FINDA)(LPCSTR,LPWIN32_FIND_DATAA);
#define CHECK(x) do { if(!(x)) { printf("Local path failure line %d: %s (%lu)\n",__LINE__,#x,GetLastError()); return 1; } } while(0)
int wmain(int argc,WCHAR **argv) {
    HMODULE guard; ATTR attr; OPEN open; FIND find; SHELL shell;ATTRA attr_a;OPENA open_a;FINDA find_a;WIN32_FIND_DATAA entry_a;
    WCHAR dir[1024],file[1100],pattern[1100],self[1024],child[1100];
    HANDLE handle; WIN32_FIND_DATAW entry; DWORD wrote,code; SHELLEXECUTEINFOW info={0};
    if(argc>1 && !lstrcmpW(argv[1],L"--child")) return 23;
    guard=LoadLibraryW(L"hcg.dll");CHECK(guard);
    attr=(ATTR)GetProcAddress(guard,"GetFileAttributesW");open=(OPEN)GetProcAddress(guard,"CreateFileW");
    find=(FIND)GetProcAddress(guard,"FindFirstFileW");shell=(SHELL)GetProcAddress(guard,"ShellExecuteExW");
    CHECK(attr && open && find && shell);
    attr_a=(ATTRA)GetProcAddress(guard,"GetFileAttributesA");open_a=(OPENA)GetProcAddress(guard,"CreateFileA");
    find_a=(FINDA)GetProcAddress(guard,"FindFirstFileA");CHECK(attr_a && open_a && find_a);
    CHECK(GetCurrentDirectoryW(1024,dir));CHECK(SUCCEEDED(StringCchCatW(dir,1024,L"\\www.example.com")));
    CHECK(CreateDirectoryW(dir,NULL) || GetLastError()==ERROR_ALREADY_EXISTS);
    StringCchPrintfW(file,1100,L"%s\\本地 report.txt",dir);
    handle=CreateFileW(file,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);CHECK(handle!=INVALID_HANDLE_VALUE);
    CHECK(WriteFile(handle,"fixture",7,&wrote,NULL));CloseHandle(handle);
    CHECK(attr(file)!=INVALID_FILE_ATTRIBUTES);
    CHECK(attr(L"www.example.com\\本地 report.txt")!=INVALID_FILE_ATTRIBUTES);
    handle=open(file,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);CHECK(handle!=INVALID_HANDLE_VALUE);CloseHandle(handle);
    StringCchPrintfW(pattern,1100,L"%s\\*",dir);handle=find(pattern,&entry);CHECK(handle!=INVALID_HANDLE_VALUE);FindClose(handle);
    handle=open_a("www.example.com\\ascii.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);CHECK(handle!=INVALID_HANDLE_VALUE);CloseHandle(handle);
    CHECK(attr_a("www.example.com\\ascii.txt")!=INVALID_FILE_ATTRIBUTES);
    handle=find_a("www.example.com\\*",&entry_a);CHECK(handle!=INVALID_HANDLE_VALUE);FindClose(handle);
    CHECK(GetModuleFileNameW(NULL,self,1024));StringCchPrintfW(child,1100,L"%s\\local-tool.exe",dir);CHECK(CopyFileW(self,child,FALSE));
    info.cbSize=sizeof(info);info.fMask=SEE_MASK_FLAG_NO_UI|SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;
    info.lpFile=child;info.lpParameters=L"--child";info.nShow=SW_HIDE;
    CHECK(shell(&info) && info.hProcess);CHECK(WaitForSingleObject(info.hProcess,5000)==WAIT_OBJECT_0);
    CHECK(GetExitCodeProcess(info.hProcess,&code) && code==23);CloseHandle(info.hProcess);
    info.lpFile=L"www.example.invalid";info.hProcess=NULL;
    CHECK(!shell(&info) && GetLastError()==ERROR_ACCESS_DENIED);
    CHECK(attr(L"\\\\example.invalid\\share\\file.txt")==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_ACCESS_DENIED);
    CHECK(attr(L"\\\\?\\UNC\\example.invalid\\share\\file.txt")==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_ACCESS_DENIED);
    CHECK(attr(L"https://example.invalid/file")==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_ACCESS_DENIED);
    DeleteFileA("www.example.com\\ascii.txt");DeleteFileW(child);DeleteFileW(file);RemoveDirectoryW(dir);
    puts("Local paths passed: A/W, Unicode, absolute/relative www directories, read/enumerate/open, URL/UNC denial.");return 0;
}
