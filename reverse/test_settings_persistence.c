/* Headless host called in place of WinMain, after the original CRT initialises.
   Execute the real config constructor/parser/setters and shutdown prefix. Only
   the following application teardown is replaced by a test-process exit. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static BYTE *image;
static BYTE *live_config;
static void StopBeforeTeardown(void) {
    typedef void (__thiscall *DESTROY)(void*);
    /* The manager calls this exact destructor during normal exit. It cancels
       the save timer and frees the model, without flushing pending changes. */
    ((DESTROY)(image+0x9fe00))(live_config);
    live_config=NULL;ExitProcess(0);
}
static LONG CALLBACK Failure(EXCEPTION_POINTERS *e) {
    char result[96]; DWORD n; HANDLE f;
    wsprintfA(result,"exception=%08lx rva=%08lx\n",e->ExceptionRecord->ExceptionCode,
        (DWORD)e->ExceptionRecord->ExceptionAddress-(DWORD)image);
    f=CreateFileW(L"probe-failure.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(f!=INVALID_HANDLE_VALUE) { WriteFile(f,result,lstrlenA(result),&n,NULL);CloseHandle(f); }
    ExitProcess(9);return EXCEPTION_CONTINUE_SEARCH;
}
static void Jump(DWORD rva,void *target) {
    DWORD old;BYTE *p=image+rva;
    VirtualProtect(p,5,PAGE_EXECUTE_READWRITE,&old);
    p[0]=0xe9;*(DWORD*)(p+1)=(DWORD)target-(DWORD)p-5;
    VirtualProtect(p,5,old,&old);FlushInstructionCache(GetCurrentProcess(),p,5);
}
extern "C" __declspec(dllexport) int __cdecl TestMain(void) {
    typedef void* (__cdecl *GET)(void);
    typedef BOOL (__thiscall *PARSE)(void*,void*);
    typedef void (__thiscall *SET)(void*,BOOL);
    typedef void (__thiscall *EXIT)(void*);
    BYTE *config;BYTE window[0xc40]={0};DWORD count,size;HANDLE f;char *json;
    struct {char *ptr;DWORD pad[3];DWORD length,capacity;} text;
    WCHAR mode[32],value[8];BOOL enabled;
    SetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS);
    image=(BYTE*)GetModuleHandleW(NULL);AddVectoredExceptionHandler(1,Failure);
    GetEnvironmentVariableW(L"HC_SETTINGS_PROBE",mode,32);
    GetEnvironmentVariableW(L"HC_SETTINGS_VALUE",value,8);enabled=value[0]==L'1';
    config=(BYTE*)((GET)(image+0xa0200))();live_config=config;
    if(!lstrcmpW(mode,L"seed")) ExitProcess(0);
    if(!lstrcmpW(mode,L"read")) {
        ExitProcess(config[0x480]==enabled && config[0x49d]==enabled ? 0:8);
    }
    f=CreateFileW(L"edited.json",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE) ExitProcess(2);
    size=GetFileSize(f,NULL);json=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size+1);
    if(!json || !ReadFile(f,json,size,&count,NULL) || count!=size) ExitProcess(3);
    CloseHandle(f);ZeroMemory(&text,sizeof(text));text.ptr=json;text.length=size;text.capacity=size;
    if(!((PARSE)(image+0xa05a0))(config,&text)) ExitProcess(4);
    ((SET)(image+0xa99f0))(config,enabled);
    ((SET)(image+0xa9a00))(config,enabled);
    if(config[0x480]!=enabled || config[0x49d]!=enabled) ExitProcess(5);
    Jump(0xbd170,StopBeforeTeardown);
    ((EXIT)(image+0x194ee0))(window);
    ExitProcess(6);return 6;
}
