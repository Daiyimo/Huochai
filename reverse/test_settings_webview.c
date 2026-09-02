/* Replay the actual faulting routine without launching the original UI.
   Imports remain unresolved. Its only pre-fault Windows call and native
   control callback are replaced by fixture functions in this process. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static void __stdcall FixtureRect(RECT *rect) { SetRectEmpty(rect); }
static BOOL __stdcall FixtureClientRect(HWND window,RECT *rect) { (void)window;SetRectEmpty(rect);return TRUE; }
static BOOL expect_crash;
static LONG CALLBACK FixtureException(EXCEPTION_POINTERS *exception) {
    BOOL exact=exception->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION &&
        exception->ExceptionRecord->ExceptionAddress==NULL;
    printf("Original settings routine: null web-call crash=%d\n",exact);fflush(stdout);
    ExitProcess(expect_crash && exact ? 0:6);
    return EXCEPTION_CONTINUE_SEARCH;
}
int wmain(int argc,WCHAR **argv) {
    HMODULE mapped; BYTE *image; DWORD old; BYTE object[0xbe0]={0}; void *vtable[20]={0}; void **control=vtable;
    typedef void (__thiscall *SHOW)(void*,BOOL); SHOW show; IMAGE_NT_HEADERS *nt;
    if(argc!=3) return 2;
    SetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS);
    expect_crash=!lstrcmpW(argv[2],L"expect-crash");
    AddVectoredExceptionHandler(1,FixtureException);
    mapped=LoadLibraryExW(argv[1],NULL,DONT_RESOLVE_DLL_REFERENCES);
    if(!mapped) {printf("Mapping failed: %lu\n",GetLastError());return 3;}
    image=(BYTE*)mapped;
    nt=(IMAGE_NT_HEADERS*)(image+((IMAGE_DOS_HEADER*)image)->e_lfanew);
    if(!VirtualProtect(image,nt->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,&old)) return 4;
    /* Loading an EXE for inspection does not resolve imports or relocations.
       Relocate only this private test mapping, then wire its two fixture calls. */
    if(*(DWORD*)(image+0x19116c)==0x83806c && (DWORD)image!=0x400000) {
        IMAGE_BASE_RELOCATION *block=(IMAGE_BASE_RELOCATION*)(image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        BYTE *end=(BYTE*)block+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        while((BYTE*)block<end && block->SizeOfBlock>=sizeof(*block)) {
            WORD *entries=(WORD*)(block+1);DWORD i,count=(block->SizeOfBlock-sizeof(*block))/sizeof(WORD);
            for(i=0;i<count;i++) if((entries[i]>>12)==IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)(image+block->VirtualAddress+(entries[i]&0xfff))+=(DWORD)image-0x400000;
            block=(IMAGE_BASE_RELOCATION*)((BYTE*)block+block->SizeOfBlock);
        }
    }
    if(!VirtualProtect(image+0x3956c0,sizeof(void*),PAGE_READWRITE,&old)) return 4;
    *(void**)(image+0x3956c0)=FixtureClientRect;
    if(!VirtualProtect(image+0x48b9fc,sizeof(void*),PAGE_READWRITE,&old)) return 4;
    *(void**)(image+0x48b9fc)=NULL;
    vtable[0x48/sizeof(void*)]=FixtureRect;
    *(void**)(object+0x7e4)=&control;
    show=(SHOW)(image+0x191140);
    show(object,TRUE);show(object,FALSE);
    puts("Original settings routine: null web-call crash=0");
    return expect_crash ? 5:0;
}
