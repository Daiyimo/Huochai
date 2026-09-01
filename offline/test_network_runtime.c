/* Probe the installed deny DLLs with realistic targets while packet capture
   runs. This is a separate harness, not UI interaction with HuoChat itself. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include <stdio.h>

typedef ULONG_PTR (__stdcall *F0)(void);
typedef ULONG_PTR (__stdcall *F2)(ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F3)(ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F4)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F5)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef ULONG_PTR (__stdcall *F6)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
typedef HMODULE (WINAPI *LOADW)(LPCWSTR);
typedef FARPROC (WINAPI *GETPROC)(HMODULE,LPCSTR);
typedef HINSTANCE (WINAPI *SHELLW)(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
typedef BOOL (WINAPI *SHELLEXW)(SHELLEXECUTEINFOW *);
typedef HANDLE (WINAPI *CREATEW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HRESULT (WINAPI *PROGID)(LPCOLESTR,LPCLSID);

#define REQUIRE(x) do { if(!(x)) { printf("FAIL line=%d test=%s error=%lu\n",__LINE__,#x,GetLastError()); return 1; } } while(0)
#define PROBE(label,x) do { REQUIRE(x); printf("PASS %s\n",label); } while(0)

int wmain(int argc,WCHAR **argv) {
    WCHAR netpath[1024],guardpath[1024]; HMODULE net,guard;
    WSADATA data; ADDRINFOW *answer=NULL; CLSID cls;
    LOADW load; GETPROC get; SHELLW shell; SHELLEXW ex; CREATEW create; PROGID progid;
    SHELLEXECUTEINFOW info={0}; unsigned i;
    const WCHAR *urls[]={L"https://example.com/huochat-offline-probe",L"http://127.0.0.1:49191/",L"https://[::1]:49191/",L"mailto:huochat-probe@example.invalid",L"C:\\huochat-probe.url"};
    const WCHAR *libraries[]={L"wininet.dll",L"winhttp.dll",L"ws2_32.dll",L"wsock32.dll",L"urlmon.dll",L"dnsapi.dll",L"netapi32.dll"};
    REQUIRE(argc==2);
    lstrcpyW(netpath,argv[1]);lstrcatW(netpath,L"\\hcn.dll");
    lstrcpyW(guardpath,argv[1]);lstrcatW(guardpath,L"\\hcg.dll");
    net=LoadLibraryW(netpath);guard=LoadLibraryW(guardpath);REQUIRE(net&&guard);
    printf("PID %lu\n",GetCurrentProcessId());
    PROBE("Winsock initialization denied",((F2)GetProcAddress(net,"WSAStartup"))(0x202,(ULONG_PTR)&data)==10091);
    PROBE("IPv4 TCP socket denied",((F3)GetProcAddress(net,"socket"))(AF_INET,SOCK_STREAM,IPPROTO_TCP)==(ULONG_PTR)INVALID_SOCKET);
    PROBE("IPv6 TCP socket denied",((F3)GetProcAddress(net,"socket"))(AF_INET6,SOCK_STREAM,IPPROTO_TCP)==(ULONG_PTR)INVALID_SOCKET);
    PROBE("IPv4 UDP socket denied",((F3)GetProcAddress(net,"socket"))(AF_INET,SOCK_DGRAM,IPPROTO_UDP)==(ULONG_PTR)INVALID_SOCKET);
    PROBE("IPv6 UDP socket denied",((F6)GetProcAddress(net,"WSASocketW"))(AF_INET6,SOCK_DGRAM,IPPROTO_UDP,0,0,0)==(ULONG_PTR)INVALID_SOCKET);
    PROBE("DNS resolution denied",((F4)GetProcAddress(net,"GetAddrInfoW"))((ULONG_PTR)L"huochat-denied-probe.invalid",0,0,(ULONG_PTR)&answer)==11001);
    PROBE("WinINet session denied",((F5)GetProcAddress(net,"InternetOpenW"))((ULONG_PTR)L"HuoChat capture probe",0,0,0,0)==0);
    PROBE("WinHTTP session denied",((F5)GetProcAddress(net,"WinHttpOpen"))((ULONG_PTR)L"HuoChat capture probe",0,0,0,0)==0);
    PROBE("URL download denied",((F5)GetProcAddress(net,"URLDownloadToFileW"))(0,(ULONG_PTR)urls[0],(ULONG_PTR)L"huochat-probe-download.tmp",0,0)==0x800C0008u);
    load=(LOADW)GetProcAddress(guard,"LoadLibraryW");get=(GETPROC)GetProcAddress(guard,"GetProcAddress");
    shell=(SHELLW)GetProcAddress(guard,"ShellExecuteW");ex=(SHELLEXW)GetProcAddress(guard,"ShellExecuteExW");
    create=(CREATEW)GetProcAddress(guard,"CreateFileW");progid=(PROGID)GetProcAddress(guard,"CLSIDFromProgID");
    REQUIRE(load&&get&&shell&&ex&&create&&progid);
    for(i=0;i<sizeof(libraries)/sizeof(libraries[0]);++i) REQUIRE(load(libraries[i])==net);
    puts("PASS dynamic network libraries redirected to deny DLL");
    PROBE("dynamic GetProcAddress uses guarded loader",get(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW")==GetProcAddress(guard,"LoadLibraryW"));
    for(i=0;i<sizeof(urls)/sizeof(urls[0]);++i) {
        REQUIRE(shell(NULL,L"open",urls[i],NULL,NULL,SW_HIDE)==(HINSTANCE)SE_ERR_ACCESSDENIED);
        ZeroMemory(&info,sizeof(info));info.cbSize=sizeof(info);info.fMask=SEE_MASK_FLAG_NO_UI|SEE_MASK_NOCLOSEPROCESS;
        info.lpFile=urls[i];info.lpVerb=L"open";info.nShow=SW_HIDE;
        REQUIRE(!ex(&info));REQUIRE(GetLastError()==ERROR_ACCESS_DENIED);REQUIRE(!info.hProcess);
    }
    puts("PASS external/loopback IPv4/IPv6 URLs, mailto and .url shell launches denied");
    PROBE("UNC SMB path denied",create(L"\\\\127.0.0.1\\huochat-probe\\file.txt",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_ACCESS_DENIED);
    PROBE("extended UNC path denied",create(L"\\\\?\\UNC\\127.0.0.1\\huochat-probe\\file.txt",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_ACCESS_DENIED);
    PROBE("HTTP COM activation lookup denied",progid(L"MSXML2.XMLHTTP.6.0",&cls)==E_ACCESSDENIED);
    PROBE("removed web engine remains unavailable",load(L"node.dll")==NULL);
    puts("All installed-DLL network probes passed.");
    return 0;
}
