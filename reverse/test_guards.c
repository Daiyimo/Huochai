/* Runs only our new deny DLLs. Does not load HuoChat/Everything or send traffic. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <shellapi.h>
#include <shlobj.h>

typedef ULONG_PTR (__stdcall *F0)(void);
typedef ULONG_PTR (__stdcall *F2)(ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F3)(ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F5)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef HMODULE (WINAPI *LOADW)(LPCWSTR);
typedef FARPROC (WINAPI *GETPROC)(HMODULE,LPCSTR);
typedef HINSTANCE (WINAPI *SHELLW)(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
typedef HRESULT (WINAPI *FOLDERW)(HWND,int,HANDLE,DWORD,LPWSTR);
typedef DWORD (WINAPI *TEMPW)(DWORD,LPWSTR);
typedef DWORD (WINAPI *TEMPA)(DWORD,LPSTR);
#define CHECK(x) do { if(!(x)) { printf("FAILED line %d\n",__LINE__); return 1; } } while(0)

int main(void) {
    HMODULE net=LoadLibraryW(L"hcn.dll"),guard=LoadLibraryW(L"hcg.dll"),redirect;
    LOADW load; GETPROC get; SHELLW shell; FOLDERW folder;
    WCHAR portable[MAX_PATH],expected[MAX_PATH]; DWORD n;
    CHECK(net && guard);
    CHECK(((F2)GetProcAddress(net,"WSAStartup"))(0x202,0)==10091);
    CHECK(((F3)GetProcAddress(net,"socket"))(2,1,6)==(ULONG_PTR)-1);
    CHECK(((F0)GetProcAddress(net,"WSAGetLastError"))()==10013);
    CHECK(GetProcAddress(net,(LPCSTR)111)==GetProcAddress(net,"WSAGetLastError"));
    CHECK(GetProcAddress(net,(LPCSTR)23)==GetProcAddress(net,"socket"));
    CHECK(((F5)GetProcAddress(net,"InternetOpenW"))(0,0,0,0,0)==0);
    CHECK(((F5)GetProcAddress(net,"HttpSendRequestW"))(0,0,0,0,0)==0);
    CHECK(((F5)GetProcAddress(net,"URLDownloadToFileA"))(0,0,0,0,0)==0x800C0008u);
    load=(LOADW)GetProcAddress(guard,"LoadLibraryW");
    get=(GETPROC)GetProcAddress(guard,"GetProcAddress");
    shell=(SHELLW)GetProcAddress(guard,"ShellExecuteW");
    folder=(FOLDERW)GetProcAddress(guard,"SHGetFolderPathW");
    CHECK(load && get && shell && folder);
    redirect=load(L"wininet.dll"); CHECK(redirect==net);
    CHECK(load(L"WS2_32.DLL")==net);
    CHECK(load(L"C:\\Windows\\System32\\winhttp.dll")==net);
    CHECK(load(L"node.dll")==NULL);
    CHECK(get(redirect,"InternetOpenW")==GetProcAddress(net,"InternetOpenW"));
    CHECK(get(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW")==GetProcAddress(guard,"LoadLibraryW"));
    CHECK(get(GetModuleHandleW(L"shell32.dll"),"SHGetFolderPathW")==GetProcAddress(guard,"SHGetFolderPathW"));
    CHECK(SUCCEEDED(folder(NULL,CSIDL_LOCAL_APPDATA,NULL,0,portable)));
    n=GetModuleFileNameW(guard,expected,MAX_PATH); CHECK(n && n<MAX_PATH);
    while(n && expected[n-1]!=L'\\') --n;
    expected[n]=0; lstrcatW(expected,L"Data");
    CHECK(lstrcmpiW(portable,expected)==0);
    {
        TEMPW tw=(TEMPW)GetProcAddress(guard,"GetTempPathW");
        TEMPA ta=(TEMPA)GetProcAddress(guard,"GetTempPathA");
        WCHAR short_buffer[2]={L'Q',L'Z'},before[MAX_PATH],after[MAX_PATH];CHAR ansi[MAX_PATH*4],expected_a[MAX_PATH*4];
        DWORD length;
        CHECK(tw && ta);CHECK(GetEnvironmentVariableW(L"TEMP",before,MAX_PATH));
        lstrcatW(expected,L"\\Temp\\");length=(DWORD)lstrlenW(expected);
        CHECK(tw(0,NULL)==length+1 && tw(2,short_buffer)==length+1 && short_buffer[0]==L'Q' && short_buffer[1]==L'Z');
        CHECK(tw(MAX_PATH,portable)==length && !lstrcmpW(portable,expected));
        CHECK(WideCharToMultiByte(CP_ACP,0,expected,-1,expected_a,sizeof(expected_a),NULL,NULL));
        CHECK(ta(sizeof(ansi),ansi)==strlen(expected_a) && !lstrcmpA(ansi,expected_a));
        CHECK(GetEnvironmentVariableW(L"TEMP",after,MAX_PATH) && !lstrcmpW(before,after));
        CHECK(get(GetModuleHandleW(L"kernel32.dll"),"GetTempPathW")==GetProcAddress(guard,"GetTempPathW"));
    }
    CHECK(load(L"\\\\example.invalid\\share\\x.dll")==NULL);
    CHECK(shell(NULL,L"open",L"https://example.invalid/",NULL,NULL,0)==(HINSTANCE)5);
    CHECK(shell(NULL,L"open",L"about:blank",NULL,NULL,0)==(HINSTANCE)5);
    CHECK(shell(NULL,L"open",L"C:\\test.url",NULL,NULL,0)==(HINSTANCE)5);
    CHECK(GetProcAddress(guard,"GetTickCount")!=NULL);
    CHECK(GetModuleHandleW(L"wininet.dll")==NULL);
    CHECK(GetModuleHandleW(L"ws2_32.dll")==NULL);
    #include "all_exports_test.inc"
    puts("Guard harness passed: network failures, portable AppData, x86 stack conventions, loader routing, URL/UNC rejection, local forwarding.");
    return 0;
}
